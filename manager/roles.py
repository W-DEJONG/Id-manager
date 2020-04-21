import re


def split_role(role):
    """
    Split a role string in the format `name[value,value]`
    Returns a tuple with name and a list of values.
    """
    regex = r"^([a-zA-Z0-9\-\_\:]+)(?:\[([a-zA-Z0-9\-\_,\.]*|\*)\])?$"
    matches = re.fullmatch(regex, role)
    if matches:
        name = matches.group(1)
        values = matches.group(2)
        return name, set(values.split(',')) if values else set()
    else:
        raise ValueError('Invalid role: `%s`' % role)


def join_role(name, values):
    """ Returns a role string in the format `name[value,value]` for given name and value list. """
    values_str = '[' + ','.join(values) + ']' if values else ''
    return name + values_str


class Roles:
    def __init__(self, roles_str=None):
        self._roles = dict()
        if roles_str:
            self.set_roles_str(roles_str)

    def __str__(self):
        return self.get_roles_str()

    def __repr__(self):
        return '<Roles:"%s">' % self.get_roles_str()

    def set_roles_str(self, roles_str):
        for role in roles_str.split():
            if role != '':
                name, values = split_role(role)
                self._roles[name] = values

    def get_roles_str(self):
        return ' '.join([join_role(n, v) for n, v in self._roles.items()])

    def has_role(self, name):
        return name in self._roles

    def get_roles(self):
        return self._roles.keys()

    def add_role(self, role_str):
        name, values = split_role(role_str)
        self._roles[name] = values

    def del_role(self, role):
        del self._roles[role]

    def get_role_values(self, role):
        return self._roles.get(role)

    def has_role_value(self, role, value):
        return role in self._roles and value in self._roles[role]

    def add_role_value(self, role, value):
        if re.match('', value):
            self._roles[role].add(value)
        else:
            raise ValueError('Invalid role value: `%s`' % value)

    def del_role_value(self, role, value):
        self._roles[role].discard(value)

    def validate_roles(self, roles_str, operator='AND'):
        resource_roles = set(self._roles.keys())
        if not resource_roles:
            return True
        user_roles = set(roles_str.strip().split())
        if operator == 'AND':
            return resource_roles.issuperset(user_roles)
        if operator == 'OR':
            return bool(user_roles & resource_roles)
        if callable(operator):
            return operator(user_roles, resource_roles)
        raise ValueError('Invalid operator value')

    def merge_roles(self, roles):
        for key, values in roles._roles.items():
            if key in self._roles:
                self._roles[key] |= values
            else:
                self._roles[key] = values

    def remove_roles(self, roles):
        for key, values in roles._roles.items():
            if key in self._roles:
                if len(values):
                    self._roles[key] -= values
                else:
                    del self._roles[key]
