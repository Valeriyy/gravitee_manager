# Recursive merge two dictionaries
def deep_merge(dict1, dict2):
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result

# Recursive remove item form dict by key or key-value
def remove1(t, path):
    if not path:
        return t
    elif isinstance(t, list):
        return list(remove1(e, path) for e in t)
    elif isinstance(t, dict):
        if len(path) == 1:
            return {k:remove1(v, path) for (k,v) in t.items() if not k == path[0] }
        else:
            return {k:remove1(v, path[1:]) if k == path[0] else remove1(v, path) for (k,v) in t.items()}
    else:
        return t

def remove(t, *paths):
    for p in paths:
        t = remove1(t, p)
    return t

