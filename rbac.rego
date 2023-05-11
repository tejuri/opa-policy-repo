sites = [
    {"name": "prod"},
    {"name": "smoke1"},
    {"name": "dev"}
]
q[name] { sites[_].name = name }
