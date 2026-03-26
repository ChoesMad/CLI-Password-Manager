import sys
from pathlib import Path

import click
from cryptography.fernet import InvalidToken
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

import database as db
import crypto_utils as cu

DB_PATH: Path = Path("vault.db")
console: Console = Console()

def _print_success(message: str) -> None:
    console.print(f"[bold green]✔[/bold green]  {message}")


def _print_error(message: str) -> None:
    console.print(f"[bold red]✘[/bold red]  {message}", stderr=True)


def _print_info(message: str) -> None:
    console.print(f"[bold cyan]ℹ[/bold cyan]  {message}")


def _prompt_master_password(confirm: bool = False) -> str:
    password = Prompt.ask(":locked: [bold]Master Password[/bold]", password=True)
    if confirm:
        repeated = Prompt.ask(":locked: [bold]Repeat Master Password[/bold]", password=True)
        if password != repeated:
            _print_error("Passwords are not identical. Operation cancelled.")
            sys.exit(1)
    return password


def _verify_master_or_exit(master_password: str) -> None:
    result = db.load_master_password(DB_PATH)
    if result is None:
        _print_error("Vault has not been initialized. Run: py main.py init")
        sys.exit(1)
    stored_hash, salt = result
    if not cu.verify_password(master_password, salt, stored_hash):
        _print_error("Incorrect Master Password.")
        sys.exit(1)

@click.group()
def cli() -> None:
    db.initialize_database(DB_PATH)

@cli.command("init")
def cmd_init() -> None:
    console.print(
        Panel(
            "[bold]Password vault initialization[/bold]\n"
            "[dim]Master Password is never stored in plain text.[/dim]",
            title="🔐 Password Manager",
            border_style="cyan",
        )
    )

    if db.is_initialized(DB_PATH):
        if not Confirm.ask(
            "[yellow]Vault already exists. Are you sure you want to overwrite?[/yellow]"
        ):
            _print_info("Operation cancelled.")
            return

    master_password = _prompt_master_password(confirm=True)

    try:
        salt = cu.generate_salt()
        password_hash = cu.hash_password(master_password, salt)
        db.save_master_password(password_hash, salt, DB_PATH)
    except Exception as exc:
        _print_error(f"Error during initialization: {exc}")
        sys.exit(1)

    _print_success("Vault initialized successfully.")

@cli.command("add")
@click.option(
    "--service", "-s",
    prompt="Service name",
    help="Service name or URL",
)
@click.option(
    "--username", "-u",
    prompt="Username / e-mail",
    help="Login or email address assigned to the account.",
)
def cmd_add(service: str, username: str) -> None:
    if not db.is_initialized(DB_PATH):
        _print_error("The vault was not initialized. Run: py main.py init")
        sys.exit(1)

    master_password = _prompt_master_password()
    _verify_master_or_exit(master_password)

    password = Prompt.ask(f":key: Password for [bold]{service}[/bold]", password=True)
    if not password:
        _print_error("Password cannot be empty.")
        sys.exit(1)

    try:
        entry_salt = cu.generate_salt()
        cipher = cu.VaultCipher(master_password, entry_salt)
        encrypted = cipher.encrypt(password)
        credential_id = db.add_credential(service, username, encrypted, entry_salt, DB_PATH)
    except Exception as exc:
        _print_error(f"Error during saving: {exc}")
        sys.exit(1)

    _print_success(
        f"Password for [bold]{service}[/bold] has been saved (ID: {credential_id})."
    )

@cli.command("get")
@click.argument("service")
def cmd_get(service: str) -> None:
    if not db.is_initialized(DB_PATH):
        _print_error("The vault was not initialized. Run: py main.py init")
        sys.exit(1)

    master_password = _prompt_master_password()
    _verify_master_or_exit(master_password)

    try:
        row = db.get_credential(service, DB_PATH)
    except Exception as exc:
        _print_error(f"Database read error: {exc}")
        sys.exit(1)

    if row is None:
        _print_error(f"Entry not found for service: [bold]{service}[/bold]")
        sys.exit(1)

    credential_id, db_service, username, encrypted_password, entry_salt = row

    try:
        cipher = cu.VaultCipher(master_password, entry_salt)
        plain_password = cipher.decrypt(encrypted_password)
    except InvalidToken:
        _print_error(
            "Cannot decrypt password. "
            "Probably data is corrupted or key is incorrect."
        )
        sys.exit(1)

    console.print(
        Panel(
            f"[dim]ID:[/dim]           [bold]{credential_id}[/bold]\n"
            f"[dim]Service:[/dim]       [bold cyan]{db_service}[/bold cyan]\n"
            f"[dim]User:[/dim]   [bold]{username}[/bold]\n"
            f"[dim]Password:[/dim]        [bold green]{plain_password}[/bold green]",
            title="🔑 Credentials",
            border_style="green",
            padding=(1, 2),
        )
    )


@cli.command("list")
def cmd_list() -> None:
    if not db.is_initialized(DB_PATH):
        _print_error("The vault was not initialized. Run: py main.py init")
        sys.exit(1)

    try:
        credentials = db.list_credentials(DB_PATH)
    except Exception as exc:
        _print_error(f"Database read error: {exc}")
        sys.exit(1)

    if not credentials:
        _print_info("Vault is empty. Add a password: py main.py add")
        return

    table = Table(
        title="🔐 Password vault",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True,
        expand=False,
    )
    table.add_column("ID", style="dim", justify="right", no_wrap=True)
    table.add_column("Service", style="bold cyan", min_width=20)
    table.add_column("user", style="white", min_width=25)

    for credential_id, service, username in credentials:
        table.add_row(str(credential_id), service, username)

    console.print()
    console.print(table)
    console.print(
        f"\n[dim]Total entries: [bold]{len(credentials)}[/bold][/dim]"
    )

@cli.command("delete")
@click.argument("credential_id", type=int)
def cmd_delete(credential_id: int) -> None:
    if not db.is_initialized(DB_PATH):
        _print_error("The vault was not initialized. Run: py main.py init")
        sys.exit(1)

    master_password = _prompt_master_password()
    _verify_master_or_exit(master_password)

    try:
        row = db.get_credential_by_id(credential_id, DB_PATH)
    except Exception as exc:
        _print_error(f"Database error read: {exc}")
        sys.exit(1)

    if row is None:
        _print_error(f"Entry not found ID: [bold]{credential_id}[/bold]")
        sys.exit(1)

    _, service, username, _, _ = row
    console.print(
        f"[yellow]Entry to delete:[/yellow] "
        f"[bold]{service}[/bold] ({username})"
    )

    if not Confirm.ask("[red]Are you sure you want to delete this entry?[/red]"):
        _print_info("Operation canceled.")
        return

    try:
        deleted = db.delete_credential(credential_id, DB_PATH)
    except Exception as exc:
        _print_error(f"Error during deletion: {exc}")
        sys.exit(1)

    if deleted:
        _print_success(f"Entry [bold]{service}[/bold] (ID: {credential_id}) has been deleted.")
    else:
        _print_error("Failed to delete entry.")

if __name__ == "__main__":
    cli()
