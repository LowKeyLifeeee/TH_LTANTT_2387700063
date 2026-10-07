import click

if __package__:
    from .modules.runner import run_task, parse_ports
else:
    from modules.runner import run_task, parse_ports


@click.command()
@click.option("--target", prompt="Target IP", help="Dia chi IP muc tieu.")
@click.option("--ports", default="22,80,443", help="Danh sach cong hoac khoang, vi du 20-25,80.")
@click.option("--rate-limit", default=10.0, type=click.FloatRange(0.1, 100), help="So ket noi moi giay.")
@click.option("--mode", default="all", type=click.Choice(["all", "scan", "service", "banner", "map", "vuln"]))
@click.option("--whitelist", multiple=True, help="IP duoc phep; co the lap lai tuy chon.")
@click.option("--blacklist", multiple=True, help="IP bi chan; co the lap lai tuy chon.")
def cli(target, ports, rate_limit, mode, whitelist, blacklist):
    try:
        result = run_task(target, parse_ports(ports), mode, rate_limit, whitelist, blacklist)
    except ValueError as error:
        raise click.ClickException(str(error)) from error
    for key, value in result.items():
        click.echo(f"--- {key.upper()} ---\n{value}")


if __name__ == "__main__":
    cli()
