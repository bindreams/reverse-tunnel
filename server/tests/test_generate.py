import hashlib

import yaml

from ctl.generate import alias_key, render_compose

T = "t.test"
H = "sha256:" + "1" * 64


def labels_of(hosts, aliases):
    text = render_compose(hosts, aliases, T)
    assert "? " not in text  # no YAML complex keys
    doc = yaml.safe_load(text)
    assert list(doc["services"]) == ["reverse-tunnel-plugin"]
    pairs = doc["services"]["reverse-tunnel-plugin"]["labels"]
    assert pairs == sorted(pairs)
    return dict(pair.split("=", 1) for pair in pairs)


def test_alias_key_is_dot_free_sha256():
    key = alias_key("movies.example.test")
    assert key == "reverse-tunnel-alias-" + hashlib.sha256(b"movies.example.test").hexdigest()
    assert "." not in key


def test_compose_zero_hosts_has_no_router_labels():
    labels = labels_of({}, {})
    assert labels["traefik.enable"] == "true"
    assert labels["traefik.expose"] == "true"
    assert not [k for k in labels if k.startswith("traefik.http.routers.")]


def test_compose_hosts():
    labels = labels_of({"b": H, "a": H}, {})
    certs = "traefik.http.routers.reverse-tunnel-certs"
    assert labels[f"{certs}.rule"] == "Host(`certs.invalid`)"
    assert labels[f"{certs}.service"] == "noop@internal"
    assert labels[f"{certs}.entrypoints"] == "websecure"
    assert labels[f"{certs}.tls.certresolver"] == "letsencrypt"
    assert labels[f"{certs}.tls.domains[0].main"] == "*.a.t.test"
    assert labels[f"{certs}.tls.domains[0].sans"] == "a.t.test"
    assert labels[f"{certs}.tls.domains[1].main"] == "*.b.t.test"
    assert labels[f"{certs}.tls.domains[1].sans"] == "b.t.test"
    assert labels["traefik.http.services.reverse-tunnel-plugin.loadbalancer.server.port"] == "9000"


def test_compose_alias():
    labels = labels_of({}, {"movies.example.test": "jellyfin.a.t.test"})
    key = alias_key("movies.example.test")
    router = f"traefik.http.routers.{key}"
    assert labels[f"{router}.rule"] == "Host(`movies.example.test`)"
    assert labels[f"{router}.entrypoints"] == "websecure"
    assert labels[f"{router}.tls"] == "true"
    assert labels[f"{router}.tls.certresolver"] == "letsencrypt"
    assert labels[f"{router}.middlewares"] == key
    assert labels[f"{router}.service"] == "reverse-tunnel-frps-vhost@docker"
    assert labels[f"traefik.http.middlewares.{key}.headers.customrequestheaders.Host"] == "jellyfin.a.t.test"
    assert labels["traefik.http.services.reverse-tunnel-plugin.loadbalancer.server.port"] == "9000"
