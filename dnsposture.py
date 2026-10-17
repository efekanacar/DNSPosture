#!/usr/bin/env python3
"""DNSPosture: salt okunur DNS ve e-posta politikası ön incelemesi."""

import argparse
import ipaddress
import json
import math
import re
import sys
from datetime import datetime, timezone

import dns.exception
import dns.resolver


def domain_name(value):
    """URL, IP veya sorgu enjeksiyonu yerine bir DNS hostname kabul et."""
    try:
        name = value.rstrip('.').encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise argparse.ArgumentTypeError('Geçersiz domain.') from exc
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise argparse.ArgumentTypeError('IP adresi yerine domain girin.')
    if len(name) > 253 or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
        for label in name.split('.')
    ):
        raise argparse.ArgumentTypeError('Şema veya yol içermeyen geçerli bir domain girin.')
    return name


def positive_seconds(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('Timeout pozitif bir sayı olmalı.') from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError('Timeout sonlu ve pozitif olmalı.')
    return number


def query(resolver, name, kind):
    result = {'name': name, 'type': kind, 'status': 'ok', 'records': []}
    try:
        answer = resolver.resolve(name + '.', kind, search=False)
        result['ttl'] = answer.rrset.ttl
        result['records'] = [
            b''.join(item.strings).decode('utf-8', errors='replace')
            if kind == 'TXT' else item.to_text() for item in answer
        ]
    except dns.resolver.NXDOMAIN:
        result['status'] = 'nxdomain'
    except dns.resolver.NoAnswer:
        result['status'] = 'no_answer'
    except dns.exception.Timeout:
        result.update(status='timeout', error='DNS sorgusu zaman aşımına uğradı.')
    except dns.resolver.NoNameservers:
        result.update(status='error', error='Kullanılabilir DNS sunucusu yanıtı alınamadı.')
    except (dns.exception.DNSException, OSError) as exc:
        result.update(status='error', error=str(exc))
    return result


def finding(report, code, message, recommendation):
    report['findings'].append({'code': code, 'message': message,
                               'recommendation': recommendation})


def analyze_spf(result, report):
    records = [r for r in result['records'] if re.match(r'^v=spf1(?:\s|$)', r, re.I)]
    analysis = {'status': 'unknown', 'records': records}
    if result['status'] not in ('ok', 'no_answer', 'nxdomain'):
        return analysis
    analysis['status'] = 'present' if records else 'not_found'
    if not records:
        finding(report, 'spf_not_found', 'Sorgulanan domainde SPF bulunamadı; e-posta kullanımına göre risk oluşturabilir.',
                'Gönderim kaynaklarını belirleyip uygun tek bir SPF kaydı yayınlamayı değerlendirin.')
        return analysis
    if len(records) > 1:
        analysis['status'] = 'multiple'
        finding(report, 'spf_multiple', 'Birden fazla SPF kaydı SPF değerlendirme hatasına yol açabilir.',
                'Yetkili göndericileri tek SPF kaydında birleştirin.')
        return analysis
    terms = records[0].split()[1:]
    all_terms = [t for t in terms if re.fullmatch(r'[+~?\-]?all', t, re.I)]
    redirects = [t for t in terms if t.lower().startswith('redirect=')]
    analysis.update(terms=terms, all=all_terms[0] if all_terms else None,
                    redirect=redirects, recursive_evaluation=False)
    if all_terms:
        qualifier = all_terms[0][0] if all_terms[0][0] in '+-~?' else '+'
        analysis['all_qualifier'] = qualifier
        if qualifier in ('+', '?', '~'):
            finding(report, 'spf_all_' + {'+': 'pass', '?': 'neutral', '~': 'softfail'}[qualifier],
                    f'SPF ilk all mekanizması {all_terms[0]}: ' +
                    {'+': 'bu noktaya ulaşan tüm kaynaklar yetkilendirilir.',
                     '?': 'bu noktaya ulaşan kaynaklar için nötr sonuç istenir.',
                     '~': 'bu noktaya ulaşan kaynaklar için softfail istenir; bu tek başına açık değildir.'}[qualifier],
                    'Meşru göndericileri doğrulayın; all davranışını e-posta politikanıza göre değerlendirin.')
    elif not redirects:
        finding(report, 'spf_no_terminal', 'SPF içinde all veya redirect yok; eşleşmeyen kaynaklar nötr sonuç alabilir.',
                'Gönderim ihtiyaçlarına göre sonlandırıcı politika belirleyin.')
    return analysis


def parse_tags(record):
    tags, errors = {}, []
    for part in record.split(';'):
        if not part.strip():
            continue
        key, sep, value = part.strip().partition('=')
        if not sep or not key or key in tags:
            errors.append('Eksik eşittir, boş veya yinelenen etiket: ' + key)
        else:
            tags[key] = value.strip()
    return tags, errors


def analyze_dmarc(result, report):
    records = [r for r in result['records'] if re.match(r'^v=DMARC1(?:\s*;|\s*$)', r)]
    analysis = {'status': 'unknown', 'records': records, 'scope': 'direct_record_only'}
    if result['status'] not in ('ok', 'no_answer', 'nxdomain'):
        return analysis
    if not records:
        analysis['status'] = 'not_found'
        finding(report, 'dmarc_not_found', 'Doğrudan DMARC kaydı bulunamadı. Üst domain politikası uygulanabilir; etkin politika belirlenmedi.',
                'Üst domain politikalarını ve e-posta kullanımını kontrol edin; gerekirse DMARC yayınlayın.')
        return analysis
    if len(records) != 1:
        analysis['status'] = 'multiple'
        finding(report, 'dmarc_multiple', 'Birden fazla DMARC kaydı politika değerlendirmesini engelleyebilir.',
                'Tek bir geçerli DMARC kaydı yayınlayın.')
        return analysis
    tags, errors = parse_tags(records[0])
    policy = tags.get('p')
    if policy not in ('none', 'quarantine', 'reject'):
        errors.append('p etiketi eksik veya desteklenen bir politika değil.')
    for tag in ('sp', 'np'):
        if tag in tags and tags[tag] not in ('none', 'quarantine', 'reject'):
            errors.append(tag + ' politikası tanınmıyor.')
    analysis.update(status='review' if errors else 'present', tags=tags,
                    policy=policy, checks=errors)
    if errors:
        finding(report, 'dmarc_format', 'Temel DMARC biçim kontrolünde sorun: ' + ' '.join(errors),
                'Kaydı güncel DMARC standardına göre doğrulayın.')
    elif policy == 'none':
        finding(report, 'dmarc_monitoring', 'DMARC p=none: başarısız iletiler için özel karantina veya ret talep edilmez.',
                'Meşru SPF/DKIM hizalamasını ve raporları inceleyerek daha sıkı politikaya geçişi değerlendirin.')
    analysis['policy_meaning'] = {'none': 'İzleme / özel işlem talebi yok',
                                  'quarantine': 'Başarısız iletiler için karantina talebi',
                                  'reject': 'Başarısız iletiler için ret talebi'}.get(policy)
    return analysis


def analyze(domain, selector, timeout):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    report = {'tool': 'DNSPosture', 'domain': domain,
              'timestamp': datetime.now(timezone.utc).isoformat(), 'findings': [],
              'limitations': ['Salt okunur, temel yapılandırma incelemesidir; bulgular kesin güvenlik açığı değildir.',
                              'SPF include/redirect zincirleri ve DNS lookup sınırı doğrulanmaz.',
                              'DMARC üst domain keşfi ve etkin politika değerlendirmesi yapılmaz.',
                              'DNSSEC, DKIM imzası, anahtar kriptografisi ve gerçek ileti hizalaması doğrulanmaz.',
                              'Kayıt varlığı e-posta teslimatını veya güvenliğini garanti etmez.']}
    report['dns'] = {kind: query(resolver, domain, kind)
                     for kind in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA')}
    report['spf'] = analyze_spf(report['dns']['TXT'], report)
    dmarc = query(resolver, '_dmarc.' + domain, 'TXT')
    report['dmarc_query'] = dmarc
    report['dmarc'] = analyze_dmarc(dmarc, report)
    report['dkim'] = {'status': 'not_checked', 'reason': 'Selector belirtilmedi.'}
    queries = list(report['dns'].values()) + [dmarc]
    if selector:
        dkim = query(resolver, selector + '._domainkey.' + domain, 'TXT')
        queries.append(dkim)
        report['dkim'] = {'selector': selector, 'query': dkim, 'status': 'unknown'}
        if dkim['status'] in ('ok', 'no_answer', 'nxdomain'):
            candidates = []
            for record in dkim['records']:
                tags, errors = parse_tags(record)
                if 'p' in tags and tags.get('v', 'DKIM1') == 'DKIM1':
                    candidates.append({'tags': tags, 'checks': errors})
            report['dkim'].update(status='present' if candidates else 'not_found', keys=candidates)
            if not candidates:
                finding(report, 'dkim_selector_not_found', 'Belirtilen selector için DKIM anahtar kaydı bulunamadı; diğer selectorlar incelenmedi.',
                        'Gönderim sistemindeki etkin selector değerini doğrulayın.')
            elif any(not c['tags']['p'] for c in candidates):
                finding(report, 'dkim_revoked', 'Belirtilen selectorda boş p etiketi var; anahtar iptal edilmiş olabilir.',
                        'Selectorun halen kullanılıp kullanılmadığını kontrol edin.')
    for item in queries:
        if item['status'] in ('timeout', 'error'):
            finding(report, 'dns_query_incomplete', f"{item['name']} {item['type']} sorgusu tamamlanamadı: {item['status']}. Kayıt yokluğu çıkarılamaz.",
                    'DNS erişimini kontrol edip sorguyu tekrar çalıştırın.')
    if report['dns']['CAA']['status'] == 'no_answer':
        finding(report, 'caa_direct_not_found', 'Doğrudan CAA yanıtı yok; üst domain CAA politikası uygulanabilir. Bu tek başına açık değildir.',
                'Sertifika ihtiyaçlarını ve üst domain CAA politikasını inceleyin.')
    return report


def print_terminal(report):
    print(f"DNSPosture — {report['domain']}\nUTC: {report['timestamp']}")
    for item in list(report['dns'].values()) + [report['dmarc_query']]:
        print(f"\n{item['name']} {item['type']} [{item['status']}]")
        for record in item['records']:
            print('  ' + json.dumps(record, ensure_ascii=True))
        if 'error' in item:
            print('  ' + item['error'])
    for label in ('spf', 'dmarc', 'dkim'):
        print(f"\n{label.upper()}: " + json.dumps(report[label], ensure_ascii=True))
    print('\nOlası riskler / inceleme bulguları:')
    if not report['findings']:
        print('  Temel kontrollerde bulgu yok; bu güvenlik garantisi değildir.')
    for item in report['findings']:
        print(f"- [{item['code']}] {item['message']}\n  Öneri: {item['recommendation']}")
    print('\nKapsam ve sınırlar:')
    for note in report['limitations']:
        print('- ' + note)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('domain', type=domain_name)
    parser.add_argument('--selector', type=domain_name, help='İsteğe bağlı DKIM selector (noktalı olabilir).')
    parser.add_argument('--timeout', type=positive_seconds, default=5.0, help='Her sorgu için toplam saniye (varsayılan: 5).')
    parser.add_argument('--json', action='store_true', help='Yalnızca JSON çıktısı üret.')
    args = parser.parse_args(argv)
    if len('_dmarc.' + args.domain) > 253 or (args.selector and
            len(args.selector + '._domainkey.' + args.domain) > 253):
        parser.error('Oluşturulan DNS sorgu adı çok uzun.')
    try:
        report = analyze(args.domain, args.selector, args.timeout)
    except (dns.exception.DNSException, OSError) as exc:
        if args.json:
            print(json.dumps({'tool': 'DNSPosture', 'error': str(exc)}, ensure_ascii=True))
        else:
            print('DNS yapılandırma hatası: ' + str(exc), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2))
    else:
        print_terminal(report)
    queries = list(report['dns'].values()) + [report['dmarc_query']]
    if args.selector:
        queries.append(report['dkim']['query'])
    return 1 if any(q['status'] in ('timeout', 'error') for q in queries) else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('İşlem kullanıcı tarafından durduruldu.', file=sys.stderr)
        sys.exit(130)
