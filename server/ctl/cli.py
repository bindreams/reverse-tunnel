import argparse


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="ctl", description="Manage the reverse-tunnel bridge.")
    parser.parse_args(argv)
