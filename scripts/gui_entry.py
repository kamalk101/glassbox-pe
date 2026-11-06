"""Entry point for the Windows desktop executable."""


def main() -> None:
    from glassbox_desktop.app import main as _main

    raise SystemExit(_main())


if __name__ == "__main__":
    main()
