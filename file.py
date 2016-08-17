import os


def main():
    """docstring for main"""
    defaults_file = "defaults.conf"
    r = import_settings(defaults_file)
    for k, v in r.iteritems():
        print(k, "=", v)


def read(file):
    """docstring for read_file"""
    entries = []
    if os.path.isfile(file):
        try:
            with open(file) as f:
                print('Reading the defaults file')
                for line in f.readlines():
                    if line.startswith('#') or line.strip() == '':
                        # Skip comments and blank lines
                        continue
                    entries.append(line.strip())
        except Exception as e:
            print(e)
        else:
            pass
    return entries


def import_settings(settings_file):
    """docstring for import_settings"""
    raw_settings = read(settings_file)
    settings = {}
    if raw_settings:
        print('Reading the settings')
        for setting in raw_settings:
            s = setting.split('=', 1)
            settings[s[0].strip()] = s[1].strip()
    return settings


def get_full_path(file):
    """docstring for get_full_path"""
    base_folder = os.path.dirname(__file__)
    full_path = os.path.abspath(os.path.join(base_folder, file))
    return full_path


if __name__ == '__main__':
    main()
