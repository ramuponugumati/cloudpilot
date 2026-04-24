"""CloudPilot CLI — command-line interface for AWS infrastructure intelligence."""
import click
import json
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from cloudpilot.core import SkillRegistry, Severity
from cloudpilot.aws_client import get_regions, get_account_id
import cloudpilot.skills  # auto-register

console = Console()
SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


@click.group()
@click.option("--region", default=None, help="AWS region (default: all)")
@click.option("--profile", default=None, help="AWS CLI profile")
@click.pass_context
def cli(ctx, region, profile):
    """☁️✈️ CloudPilot — AWS Infrastructure Intelligence Platform"""
    ctx.ensure_object(dict)
    ctx.obj["region"] = region
    ctx.obj["profile"] = profile


@cli.command("scan")
@click.argument("skill_name", required=False)
@click.option("--all", "scan_all", is_flag=True, help="Run all skills")
@click.option("--export", "export_file", default=None, help="Export to JSON")
@click.pass_context
def scan(ctx, skill_name, scan_all, export_file):
    """Run scanning skills"""
    profile = ctx.obj["profile"]
    regions = get_regions(ctx.obj["region"], profile)

    if scan_all:
        skills_to_run = list(SkillRegistry.all().values())
    elif skill_name:
        s = SkillRegistry.get(skill_name)
        if not s:
            console.print(f"[red]Unknown skill: {skill_name}[/red]")
            console.print(f"Available: {', '.join(SkillRegistry.names())}")
            raise SystemExit(1)
        skills_to_run = [s]
    else:
        console.print("[yellow]Specify a skill name or use --all[/yellow]")
        console.print(f"Available: {', '.join(SkillRegistry.names())}")
        return

    console.print(Panel(f"[bold cyan]☁️✈️ CloudPilot Scan[/bold cyan]\n"
                        f"[dim]Regions: {len(regions)} | Skills: {len(skills_to_run)}[/dim]",
                        box=box.DOUBLE, style="cyan"))

    all_results = []
    for s in skills_to_run:
        console.print(f"\n[cyan]━━━ {s.name} ━━━[/cyan]")
        result = s.scan(regions, profile)
        all_results.append(result)
        if not result.findings:
            console.print(f"  [green]✓ No findings ({result.duration_seconds:.1f}s)[/green]")
        else:
            table = Table(box=box.ROUNDED, show_lines=True)
            table.add_column("Sev", width=3)
            table.add_column("Finding", max_width=40)
            table.add_column("Region", max_width=12)
            table.add_column("Resource", max_width=28)
            table.add_column("Impact/mo", justify="right", style="red")
            for f in result.findings:
                table.add_row(SEV_EMOJI.get(f.severity.value, "⚪"), f.title,
                              f.region, f.resource_id,
                              f"${f.monthly_impact:,.0f}" if f.monthly_impact else "-")
            console.print(table)

    if export_file:
        report = {"skills": {r.skill_name: {"findings": [f.to_dict() for f in r.findings]}
                             for r in all_results}}
        with open(export_file, "w") as f:
            json.dump(report, f, indent=2, default=str)
        console.print(f"[green]Exported to {export_file}[/green]")


@cli.command("discover")
@click.pass_context
def discover(ctx):
    """Discover all AWS resources and generate architecture map"""
    profile = ctx.obj["profile"]
    regions = get_regions(ctx.obj["region"], profile)
    from cloudpilot.skills.arch_mapper import ArchMapper
    mapper = ArchMapper()
    console.print("[cyan]Discovering resources...[/cyan]")
    result = mapper.discover(regions, profile)
    summary = result.get("summary", {})
    console.print(Panel(
        f"[bold]Resources: {summary.get('total_resources', 0)}[/bold]\n"
        f"Services: {', '.join(f'{k}: {v}' for k, v in summary.get('by_service', {}).items())}\n"
        f"Regions: {', '.join(summary.get('regions_scanned', []))}",
        title="[cyan]☁️ Discovery Complete[/cyan]", box=box.DOUBLE))
    if result.get("anti_patterns"):
        console.print(f"\n[yellow]⚠ {len(result['anti_patterns'])} anti-patterns detected[/yellow]")
    if result.get("service_recommendations"):
        console.print(f"[cyan]💡 {len(result['service_recommendations'])} service recommendations[/cyan]")
    if result.get("diagram"):
        console.print("\n[dim]Mermaid diagram:[/dim]")
        console.print(result["diagram"])


@cli.command("diagram")
@click.option("--view", type=click.Choice(["default", "security", "cost", "multi-region", "traffic-flow"]), default="default")
@click.option("--output", "output_file", type=click.Path(), default=None)
@click.pass_context
def diagram(ctx, view, output_file):
    """Generate architecture diagram"""
    profile = ctx.obj["profile"]
    regions = get_regions(ctx.obj["region"], profile)
    from cloudpilot.skills.arch_mapper import ArchMapper
    mapper = ArchMapper()
    console.print("[cyan]Discovering resources for diagram...[/cyan]")
    result = mapper.discover(regions, profile)
    mermaid = result.get("diagram", "")
    if output_file:
        with open(output_file, "w") as f:
            f.write(mermaid)
        console.print(f"[green]Diagram saved to {output_file}[/green]")
    else:
        console.print(mermaid)


@cli.command("iac")
@click.option("--format", "fmt", type=click.Choice(["cdk-python", "cloudformation", "terraform"]), required=True)
@click.option("--scope", default="all")
@click.option("--output", "output_file", type=click.Path(), default=None)
@click.pass_context
def iac(ctx, fmt, scope, output_file):
    """Generate Infrastructure as Code from live infrastructure"""
    profile = ctx.obj["profile"]
    regions = get_regions(ctx.obj["region"], profile)
    from cloudpilot.skills.arch_mapper import ArchMapper
    from cloudpilot.skills.iac_generator import IaCGenerator
    mapper = ArchMapper()
    console.print("[cyan]Discovering resources...[/cyan]")
    disc = mapper.discover(regions, profile)
    resources = disc.get("resources", [])
    if not resources:
        console.print("[red]No resources found[/red]")
        return
    console.print(f"[cyan]Generating {fmt} for {len(resources)} resources...[/cyan]")
    gen = IaCGenerator()
    result = gen.generate(resources, fmt, scope)
    code = result.get("code", "")
    if output_file:
        with open(output_file, "w") as f:
            f.write(code)
        console.print(f"[green]IaC saved to {output_file}[/green]")
    else:
        console.print(code)


@cli.command("chat")
@click.pass_context
def chat_cmd(ctx):
    """Interactive chat with CloudPilot agent"""
    profile = ctx.obj["profile"]
    use_legacy = os.environ.get("CLOUDPILOT_AGENT", "").lower() == "legacy"
    agent = None
    agent_type = None

    if use_legacy:
        from cloudpilot.agent.loop import CloudPilotAgent
        agent = CloudPilotAgent(profile=profile)
        agent_type = "legacy"
    else:
        try:
            from cloudpilot.agent.strands_agent import create_agent
            memory_id = os.environ.get("CLOUDPILOT_MEMORY_ID")
            agent = create_agent(profile=profile, memory_id=memory_id)
            agent_type = "strands"
        except Exception as e:
            console.print(f"[yellow]Strands agent unavailable ({e}), using legacy agent[/yellow]")
            from cloudpilot.agent.loop import CloudPilotAgent
            agent = CloudPilotAgent(profile=profile)
            agent_type = "legacy"

    engine_label = "Strands" if agent_type == "strands" else "Legacy"
    console.print(Panel(f"[bold cyan]☁️✈️ CloudPilot Chat[/bold cyan]\n[dim]Engine: {engine_label} | Type 'exit' to quit[/dim]",
                        box=box.DOUBLE, style="cyan"))
    while True:
        try:
            user_input = console.input("[bold green]You:[/bold green] ")
            if user_input.strip().lower() in ("exit", "quit", "q"):
                break
            if agent_type == "strands":
                result = agent(user_input)
                response = str(result)
            else:
                response = agent.chat(user_input)
            console.print(f"\n[bold cyan]CloudPilot:[/bold cyan] {response}\n")
        except (KeyboardInterrupt, EOFError):
            break
    console.print("[dim]Session ended.[/dim]")


@cli.command("dashboard")
@click.option("--host", default="127.0.0.1", help="Server host")
@click.option("--port", default=8080, type=int, help="Server port")
@click.option("--api-key", default=None, help="API key for auth")
@click.pass_context
def dashboard(ctx, host, port, api_key):
    """Launch the web dashboard"""
    import webbrowser
    import uvicorn
    from cloudpilot.dashboard.server import create_app
    from cloudpilot.dashboard.security import generate_api_key

    profile = ctx.obj["profile"]
    effective_key = api_key or os.environ.get("CLOUDPILOT_API_KEY")
    if not effective_key and host not in ("127.0.0.1", "localhost"):
        effective_key = generate_api_key()
        console.print(f"[yellow]⚠ Auto-generated API key: {effective_key}[/yellow]")

    app = create_app(profile=profile, api_key=effective_key)
    console.print(Panel(
        f"[bold cyan]☁️✈️ CloudPilot Dashboard[/bold cyan]\n"
        f"[dim]http://{host}:{port} | Profile: {profile or 'default'}[/dim]",
        box=box.DOUBLE, style="cyan"))
    webbrowser.open(f"http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


@cli.command("mcp")
@click.option("--transport", type=click.Choice(["stdio", "sse"]), default="stdio", help="Transport: stdio (local) or sse (HTTP)")
@click.pass_context
def mcp_cmd(ctx, transport):
    """Start MCP server for tool integration"""
    profile = ctx.obj["profile"]
    from cloudpilot.mcp_server import run_mcp_server
    if transport == "sse":
        console.print(Panel(f"[bold cyan]☁️✈️ CloudPilot MCP Server (HTTP/SSE)[/bold cyan]\n"
                            f"[dim]Profile: {profile or 'default'}[/dim]",
                            box=box.DOUBLE, style="cyan"))
    run_mcp_server(profile=profile, transport=transport)


@cli.command("serve")
@click.option("--host", default="127.0.0.1", help="Server host")
@click.option("--port", default=8080, type=int, help="Dashboard port")
@click.option("--api-key", default=None, help="API key for auth")
@click.pass_context
def serve(ctx, host, port, api_key):
    """Start Dashboard + MCP HTTP server together"""
    import threading
    import uvicorn
    from cloudpilot.dashboard.server import create_app
    from cloudpilot.dashboard.security import generate_api_key
    from cloudpilot.mcp_server import create_mcp_server

    profile = ctx.obj["profile"]
    effective_key = api_key or os.environ.get("CLOUDPILOT_API_KEY")

    console.print(Panel(
        f"[bold cyan]☁️✈️ CloudPilot Server[/bold cyan]\n"
        f"[dim]Dashboard: http://{host}:{port} | MCP: stdio\n"
        f"Profile: {profile or 'default'}[/dim]",
        box=box.DOUBLE, style="cyan"))

    app = create_app(profile=profile, api_key=effective_key)
    import webbrowser
    webbrowser.open(f"http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


@cli.command("skills")
def list_skills():
    """List available skills"""
    table = Table(title="CloudPilot Skills", box=box.ROUNDED)
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    table.add_column("Version")
    for s in SkillRegistry.all().values():
        table.add_row(s.name, s.description, s.version)
    console.print(table)


@cli.command("monitor")
@click.pass_context
@click.option("--suite", "-s", multiple=True, help="Suites to schedule (default: all)")
@click.option("--interval", "-i", type=int, default=None, help="Override interval in hours for all suites")
@click.option("--run-now", is_flag=True, help="Run all scheduled suites immediately before starting scheduler")
def monitor_cmd(ctx, suite, interval, run_now):
    """Start continuous monitoring — scheduled scans with notifications."""
    from cloudpilot.monitoring.scheduler import ScanScheduler, SUITES, DEFAULT_SCHEDULES
    from cloudpilot.monitoring.notifications import NotificationConfig

    profile = ctx.obj.get("profile")
    notify_config = NotificationConfig.from_env()

    # Build schedule config
    if suite:
        schedules = {s: DEFAULT_SCHEDULES.get(s, {"interval_hours": 24}) for s in suite if s in SUITES}
        if not schedules:
            console.print(f"[red]No valid suites. Available: {list(SUITES.keys())}[/red]")
            return
    else:
        schedules = dict(DEFAULT_SCHEDULES)

    if interval:
        schedules = {name: {"interval_hours": interval} for name in schedules}

    console.print(f"\n☁️✈️ [bold cyan]CloudPilot Continuous Monitoring[/bold cyan]\n")
    console.print(f"Profile: [green]{profile or 'default'}[/green]")
    console.print(f"Suites:  [cyan]{', '.join(schedules.keys())}[/cyan]")

    # Show notification config
    channels = []
    if notify_config.slack_webhook_url:
        channels.append("Slack")
    if notify_config.teams_webhook_url:
        channels.append("Teams")
    if notify_config.sns_topic_arn:
        channels.append("SNS")
    if notify_config.generic_webhook_url:
        channels.append("Webhook")
    console.print(f"Notify:  [yellow]{', '.join(channels) or 'None configured'}[/yellow]")
    console.print(f"Threshold: [yellow]{notify_config.min_severity}+ severity[/yellow]\n")

    table = Table(title="Schedule", box=box.ROUNDED)
    table.add_column("Suite", style="cyan")
    table.add_column("Interval")
    table.add_column("Skills")
    for name, sched in schedules.items():
        hrs = sched.get("interval_hours", 24)
        skills = SUITES.get(name, [])
        table.add_row(name, f"Every {hrs}h", ", ".join(skills))
    console.print(table)

    scheduler = ScanScheduler(profile=profile, schedules=schedules)

    if run_now:
        console.print("\n[bold]Running initial scans...[/bold]")
        for suite_name in schedules:
            console.print(f"  ▶ {suite_name}...", end=" ")
            result = scheduler.run_now(suite_name)
            findings = result.get("total_findings", 0)
            critical = result.get("critical_count", 0)
            dur = result.get("duration_seconds", 0)
            color = "red" if critical > 0 else "green"
            console.print(f"[{color}]{findings} findings ({critical} critical) in {dur}s[/{color}]")

    console.print("\n[bold green]Starting scheduler...[/bold green] (Ctrl+C to stop)\n")
    scheduler.start()

    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping scheduler...[/yellow]")
        scheduler.stop()
        console.print("[green]Scheduler stopped.[/green]")


if __name__ == "__main__":
    cli()
