import pytest
import yaml

from ctl.generate import alias_key, render_compose

T = "t.test"
H = "sha256:" + "1" * 64
MOVIES = "movies.yourdomain.org"
MUSIC = "music.yourdomain.org"
CERTS = "traefik.http.routers.reverse-tunnel-certs"


def labels_of(hosts, aliases):
    text = render_compose(hosts, aliases, T)
    assert "? " not in text  # no YAML complex keys
    doc = yaml.safe_load(text)
    assert list(doc["services"]) == ["reverse-tunnel-plugin"]
    pairs = doc["services"]["reverse-tunnel-plugin"]["labels"]
    assert pairs == sorted(pairs)
    labels = dict(pair.split("=", 1) for pair in pairs)
    assert len(labels) == len(pairs)  # distinct label keys
    return labels


def test_alias_key_literal():
    assert alias_key(MOVIES) == (
        "reverse-tunnel-alias-9b5f715605cd873986c810164a5bb74b2b2bf8efbc1eab16562320feb756a14f"
    )


def test_compose_zero_hosts_has_only_the_noop_certificate_router():
    labels = labels_of({}, {})
    assert labels["traefik.enable"] == "true"
    assert labels["traefik.expose"] == "true"
    routers = {k: v for k, v in labels.items() if k.startswith("traefik.http.routers.")}
    assert routers == {
        f"{CERTS}.rule": "Host(`certs.invalid`)",
        f"{CERTS}.entrypoints": "websecure",
        f"{CERTS}.service": "noop@internal",
    }


def test_compose_hosts():
    labels = labels_of({"b": H, "a": H}, {})
    assert labels[f"{CERTS}.rule"] == "Host(`certs.invalid`)"
    assert labels[f"{CERTS}.service"] == "noop@internal"
    assert labels[f"{CERTS}.entrypoints"] == "websecure"
    assert labels[f"{CERTS}.tls.certresolver"] == "letsencrypt"
    assert labels[f"{CERTS}.tls.domains[0].main"] == "*.a.t.test"
    assert labels[f"{CERTS}.tls.domains[0].sans"] == "a.t.test"
    assert labels[f"{CERTS}.tls.domains[1].main"] == "*.b.t.test"
    assert labels[f"{CERTS}.tls.domains[1].sans"] == "b.t.test"
    assert labels["traefik.http.services.reverse-tunnel-plugin.loadbalancer.server.port"] == "9000"


def test_compose_alias():
    labels = labels_of({}, {MOVIES: "jellyfin.a.t.test"})
    key = alias_key(MOVIES)
    router = f"traefik.http.routers.{key}"
    assert labels[f"{router}.rule"] == f"Host(`{MOVIES}`)"
    assert labels[f"{router}.entrypoints"] == "websecure"
    assert labels[f"{router}.tls"] == "true"
    assert labels[f"{router}.tls.certresolver"] == "letsencrypt"
    assert labels[f"{router}.middlewares"] == key
    assert labels[f"{router}.service"] == "reverse-tunnel-frps-vhost@docker"
    assert labels[f"traefik.http.middlewares.{key}.headers.customrequestheaders.Host"] == "jellyfin.a.t.test"
    assert labels["traefik.http.services.reverse-tunnel-plugin.loadbalancer.server.port"] == "9000"


def test_compose_hosts_and_aliases_together():
    aliases = {MUSIC: "navidrome.b.t.test", MOVIES: "jellyfin.a.t.test"}
    labels = labels_of({"b": H, "a": H}, aliases)
    for public, backend in aliases.items():
        key = alias_key(public)
        assert labels[f"traefik.http.routers.{key}.rule"] == f"Host(`{public}`)"
        assert labels[f"traefik.http.middlewares.{key}.headers.customrequestheaders.Host"] == backend
    assert labels[f"{CERTS}.tls.domains[0].main"] == "*.a.t.test"
    assert labels[f"{CERTS}.tls.domains[1].main"] == "*.b.t.test"
    assert f"{CERTS}.tls.domains[2].main" not in labels


@pytest.mark.parametrize("domain", ["test", "t.test."])
def test_render_compose_rejects_invalid_domain(domain):
    with pytest.raises(ValueError):
        render_compose({}, {}, domain)
