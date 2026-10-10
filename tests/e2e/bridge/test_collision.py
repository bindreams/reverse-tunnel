"""Two hosts claiming one label, against a real frps: who wins, who is told, and what the bridge can see."""

from bridge_support import GOOD_DOMAIN, GOOD_PASSWORD
from tunnel_support import ALREADY_EXISTS, CLOSE_PROXY, NEW_PROXY, START_PROXY, Hosts, new_label

from ctl.doctor.frps_api import list_clients, list_proxies


def assert_answers_as_websocat(stack, label: str) -> None:
    response = stack.request(f"{label}.{GOOD_DOMAIN}")
    assert (response.status_code, response.headers.get("server")) == (400, "websocat"), response.headers


def test_second_claimant_fails_and_the_first_keeps_working(bare_stack, hosts: Hosts):
    label = new_label()
    hosts.start(bare_stack, label=label)
    second = hosts.start(bare_stack, label=label, wait_for_registration=False)
    assert second.frpc_log is not None
    second.frpc_log.wait_for(ALREADY_EXISTS.format(label=label), after=0)
    assert_answers_as_websocat(bare_stack, label)


def test_the_bridge_reports_two_claimants_for_one_label(bare_stack, hosts: Hosts):
    label = new_label()
    hosts.start(bare_stack, label=label)
    second = hosts.start(bare_stack, label=label, wait_for_registration=False)
    assert second.frpc_log is not None
    second.frpc_log.wait_for(ALREADY_EXISTS.format(label=label), after=0)
    clients = list_clients(bare_stack.admin, GOOD_PASSWORD, user=label)
    proxies = list_proxies(bare_stack.admin, GOOD_PASSWORD, user=label)
    assert (len(clients.items), len(proxies.items)) == (2, 1)


def test_a_losing_claimant_takes_the_label_over_when_the_winner_leaves(bare_stack, hosts: Hosts):
    label = new_label()
    winner = hosts.start(bare_stack, label=label)
    loser = hosts.start(bare_stack, label=label, wait_for_registration=False)
    assert loser.frpc_log is not None
    loser.frpc_log.wait_for(ALREADY_EXISTS.format(label=label), after=0)
    after_failure = loser.frpc_log.mark()
    server_mark = bare_stack.frps_log.mark()
    winner.stop_frpc()
    bare_stack.frps_log.wait_for(CLOSE_PROXY.format(label=label), after=server_mark)
    loser.frpc_log.wait_for(START_PROXY, after=after_failure)
    bare_stack.frps_log.wait_for(NEW_PROXY.format(label=label), after=server_mark)
    assert_answers_as_websocat(bare_stack, label)
