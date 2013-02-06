import inspect
import pkgutil

for _, module_name, _ in pkgutil.walk_packages(__path__):
    module = __import__(module_name, globals(), locals(), [])
    for var_name, val in inspect.getmembers(module):
        if var_name.isupper():
            locals().update({var_name: val})

# vim: set ts=4 sw=4 et ai si sta:
