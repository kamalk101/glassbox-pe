"""Entry point for the Windows one-file executable."""


def main() -> None:
    from glassbox.cli import cli

    cli()


if __name__ == "__main__":
    main()
