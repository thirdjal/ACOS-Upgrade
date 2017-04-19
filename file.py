import os


def exists(filename):
    if os.path.exists(filename):
        return True
    else:
        return False


def read(filename):
    """docstring for read_file"""
    entries = []
    if os.path.isfile(filename):
        try:
            with open(filename) as f:
                for line in f.readlines():
                    if line.startswith('#') or line.strip() == '':
                        continue  # Skip comments and blank lines
                    entries.append(line.strip())
        except Exception as e:
            print(e)
    return entries


def import_settings(settings_file, settings={}):
    """docstring for import_settings"""
    raw_settings = read(settings_file)
    if raw_settings:
        for setting in raw_settings:
            if setting.find('=', 0, len(setting)) > 0:
                s = setting.split('=', 1)
                settings[s[0].strip()] = s[1].strip()
    return settings


def get_full_path(filename):
    """docstring for get_full_path"""
    base_folder = os.path.dirname(__file__)
    full_path = os.path.abspath(os.path.join(base_folder, filename))
    return full_path
