"""Derive a NEW private team config from Natalio's existing dotenv file.
Never overwrites the source or destination; no credentials are printed.
"""
import argparse
import json
from pathlib import Path
from dotenv import dotenv_values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--destination', default='.env.team')
    args = parser.parse_args()
    source, destination = Path(args.source), Path(args.destination)
    if not source.is_file():
        parser.error('Source private dotenv file not found')
    if destination.exists():
        parser.error('Destination exists; no files changed')
    values = dict(dotenv_values(source))
    names = ('users', 'assets', 'incidents', 'threats', 'logs', 'reports', 'vulnerabilities', 'notifications', 'playbooks')
    try:
        secret = values['JWT_SECRET_KEY']
        database = values['DATABASE_URL']
        tokens = json.loads(values['SERVICE_TOKENS'])
        valid = (secret and len(secret.encode()) >= 32 and 'CHANGE_ME' not in secret
                 and database.startswith('postgresql+psycopg://') and 'CHANGE_ME' not in database
                 and all(isinstance(tokens[n], str) and 32 <= len(tokens[n]) <= 8192 and tokens[n].isascii()
                         and all(33 <= ord(char) <= 126 for char in tokens[n])
                         and 'CHANGE_ME' not in tokens[n] for n in names)
                 and len(set(tokens[n] for n in names)) == len(names) and secret not in tokens.values())
        if not valid:
            raise ValueError('Invalid source config')
    except (KeyError, ValueError, TypeError):
        parser.error('Source must contain real DATABASE_URL, JWT_SECRET_KEY and nine distinct SERVICE_TOKENS of at least 32 bytes')
    template = Path(__file__).resolve().parents[2] / '.env.example'
    merged = dict(dotenv_values(template))
    merged.update({k: v for k, v in values.items() if v is not None})
    merged.update(CHRIS_DATABASE_URL=database, KARIM_DATABASE_URL=database.replace('postgresql+psycopg://', 'postgresql://', 1),
                  CHRIS_JWT_VERIFICATION_KEY=secret, KARIM_JWT_VERIFICATION_KEY=secret,
                  CHRIS_SERVICE_TOKENS=json.dumps(tokens, separators=(',', ':')),
                  KARIM_SERVICE_TOKENS=','.join(n+':'+tokens[n] for n in names))
    for name in ('incidents', 'vulnerabilities', 'notifications'):
        merged['KARIM_'+name.upper()+'_SERVICE_KEY'] = tokens[name]
    # Destination routing follows the current template, even if old CHRIS/KARIM
    # URLs are present in a source file. Review hostnames for another machine.
    current = dict(dotenv_values(template))
    for key in current:
        if key.endswith('_URL') and key.startswith(('CHRIS_', 'KARIM_')) and key not in ('CHRIS_DATABASE_URL', 'KARIM_DATABASE_URL'):
            merged[key] = current[key]
    for key in ('API_PREFIX', 'CHRIS_API_PREFIX', 'KARIM_API_PREFIX', 'JWT_ENCODE_ISSUER', 'JWT_DECODE_ISSUER',
                'JWT_ENCODE_AUDIENCE', 'JWT_DECODE_AUDIENCE', 'CHRIS_JWT_ISSUER', 'CHRIS_JWT_AUDIENCE', 'KARIM_JWT_ISSUER', 'KARIM_JWT_AUDIENCE'):
        merged[key] = current[key]
    def quote(value):
        return "'" + str(value).replace('\\', '\\\\').replace("'", "\\'") + "'"
    with destination.open('x', encoding='utf-8') as handle:
        handle.write('# Private generated team config. Never commit or share publicly.\n')
        for key, value in merged.items():
            if value is not None:
                handle.write(key + '=' + quote(value) + '\n')
    print('Created new private team config. Review it locally; existing files were preserved.')


if __name__ == '__main__':
    main()
