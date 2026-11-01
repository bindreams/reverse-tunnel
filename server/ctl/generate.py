import hashlib

import yaml

PLUGIN_SERVICE = "reverse-tunnel-plugin"  # the compose service and its Traefik service
CERTS_ROUTER = "reverse-tunnel-certs"
FRPS_VHOST_SERVICE = "reverse-tunnel-frps-vhost"  # defined on frps's labels


def alias_key(public: str) -> str:
    """The Traefik router and middleware name for an alias: dot-free, so it is safe inside a label key."""
    return "reverse-tunnel-alias-" + hashlib.sha256(public.encode()).hexdigest()


def render_compose(hosts: dict[str, str], aliases: dict[str, str], domain: str) -> str:
    """Compose override that adds the registries' Traefik labels to the plugin service."""
    labels = {
        "traefik.enable": "true",
        "traefik.expose": "true",
        # Without a service port label Traefik drops the container's whole configuration.
        f"traefik.http.services.{PLUGIN_SERVICE}.loadbalancer.server.port": "9000",
    }
    certs = f"traefik.http.routers.{CERTS_ROUTER}"
    if hosts:
        # Only a stand-in router to carry the certificate domains; nothing routes to it.
        labels |= {
            f"{certs}.rule": "Host(`certs.invalid`)",
            f"{certs}.service": "noop@internal",
            f"{certs}.entrypoints": "websecure",
            f"{certs}.tls.certresolver": "letsencrypt",
        }
    for i, host in enumerate(sorted(hosts)):
        labels[f"{certs}.tls.domains[{i}].main"] = f"*.{host}.{domain}"
        labels[f"{certs}.tls.domains[{i}].sans"] = f"{host}.{domain}"
    for public, backend in sorted(aliases.items()):
        key = alias_key(public)
        router = f"traefik.http.routers.{key}"
        labels |= {
            f"{router}.rule": f"Host(`{public}`)",
            f"{router}.entrypoints": "websecure",
            f"{router}.tls": "true",
            f"{router}.tls.certresolver": "letsencrypt",
            f"{router}.middlewares": key,
            f"{router}.service": f"{FRPS_VHOST_SERVICE}@docker",
            f"traefik.http.middlewares.{key}.headers.customrequestheaders.Host": backend,
        }
    # Compose's list form: label keys this long would make PyYAML emit complex `? ` keys.
    pairs = sorted(f"{key}={value}" for key, value in labels.items())
    return yaml.safe_dump({"services": {PLUGIN_SERVICE: {"labels": pairs}}}, sort_keys=False)
