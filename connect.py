import ipaddress
import logging
import shlex
import webbrowser
from time import sleep

import boto3
import click
import subprocess
import json
import requests
import dpath.util

from pathlib import Path
from functools import lru_cache
from pprint import pprint
from typing import List
from sshpubkeys import SSHKey, InvalidKeyError

PRESETS = {"rabbitmq": {"name": "rabbitmq-1", "port": 15672}}

logger = logging.getLogger()
process = None


@click.group()
def cli():
    pass


def execute(cmd):
    global process
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    for stdout_line in iter(process.stdout.readline, ""):
        yield stdout_line
    process.stdout.close()
    return_code = process.wait()
    if return_code:
        raise subprocess.CalledProcessError(return_code, cmd)


def start_port_forward(instance_id: str, remote_port: int = 22, local_port: int = None):
    parameters = {"portNumber": [str(remote_port)]}

    if local_port:
        parameters["localPortNumber"] = [str(local_port)]

    for line in execute([
        "/usr/local/bin/aws",
        "ssm",
        "start-session",
        "--target",
        instance_id,
        "--document-name",
        "AWS-StartPortForwardingSession",
        "--parameters",
        f"{json.dumps(parameters)}",
    ]):
        print(line)
        if f"Port {local_port} opened for session" in line:
            print("Open port detected")
            return


@lru_cache()
def get_instance(instance_id: str):
    client = boto3.client("ec2")
    return client.describe_instances(InstanceIds=[instance_id])


def get_instance_details(instance_id: str, path: str, *, multiple=False, first=True):
    if first:
        path = "Reservations/0/Instances/0/" + path
    if multiple:
        return dpath.util.values(get_instance(instance_id), path)
    return dpath.util.get(get_instance(instance_id), path)


def build_filter(name: str, *values):
    return {"Name": name, "Values": list(values)}


@lru_cache()
def check_ssm_plugin() -> bool:
    try:
        subprocess.run("session-manager-plugin", check=True, shell=True)
        return True
    except subprocess.CalledProcessError:
        return False


@lru_cache()
def get_my_ip() -> ipaddress.IPv4Address:
    response = requests.get("https://v4.ident.me")
    return ipaddress.ip_address(response.text)


def check_instance_open(instance_id: str = None, port: int = 22):
    client = boto3.client("ec2")
    response = client.describe_security_groups(
        GroupIds=get_instance_details(
            instance_id, "SecurityGroups/*/GroupId", multiple=True
        )
    )
    my_ip = get_my_ip()

    for ip, from_port in zip(
        dpath.util.values(
            response, "SecurityGroups/*/IpPermissions/*/IpRanges/*/CidrIp"
        ),
        dpath.util.values(response, "SecurityGroups/*/IpPermissions/FromPort"),
    ):
        if port == from_port and my_ip in ipaddress.ip_network(ip):
            return True
    return False


def find_instances(name: str = None) -> List[str]:
    client = boto3.client("ec2")
    filters = [build_filter("instance-state-name", "running")]
    if name:
        filters.append(build_filter("tag:Name", name))
    response = client.describe_instances(Filters=filters)
    return dpath.util.values(response, "Reservations/*/Instances/*/InstanceId")


def get_instance_id(name: str = None):
    if name in PRESETS:
        name = PRESETS[name]["name"]

    instance_ids = find_instances(name)
    if len(instance_ids) == 0:
        click.echo("No matched instances")
        assert name, "No running instances found in region"
        click.echo("Returning all instances")
        get_instance_id()

    if len(instance_ids) == 1:
        return instance_ids[0]
    click.echo("Multiple instances detected")
    for index, instance in enumerate(instance_ids):
        click.echo(f"{index + 1}: {instance}")
    value = click.prompt("Which instance would you like", type=int)
    assert 0 <= value < len(instance_ids), "Invalid instance selection"
    return instance_ids[value - 1]


@cli.command()
@click.argument("name")
def session(name):
    if name in PRESETS:
        name = PRESETS[name]["name"]
    subprocess.run(
        [f"aws ssm start-session --target {get_instance_id(name)}"], shell=True
    )


def check_ssh_key(key_name: str) -> bool:
    client = boto3.client("ec2")
    response = client.describe_key_pairs(KeyNames=[key_name])
    fingerprint = dpath.util.get(response, "KeyPairs/0/KeyFingerprint")
    path = str(Path.home() / ".ssh" / f"{key_name}.pub")
    # try:
    with open(path, "r") as file:
        ssh = SSHKey(file.read(), strict=True)
        ssh.parse()
        assert (
            ssh.hash_md5() == fingerprint
        ), f"Local key {ssh.hash_md5()} does not match {fingerprint}"
        return True
    # except InvalidKeyError:
    #     return False
    # except AssertionError:
    #     logger.debug(f"Local key does not match fingerprint")
    #     return False
    # except FileNotFoundError:
    #     print(path)
    #     logger.debug(f"SSH key cannot be found at {path}")
    #     return False


def allow_port(instance_id, port):
    client = boto3.resource('ec2')

    client.client.authorize_security_group_ingress(
        CidrIp=f'{get_my_ip()}/32',
        FromPort=port,
        GroupId=get_instance_details(
        instance_id, "SecurityGroups/0/GroupId"
    ),

        IpProtocol='-1',
        ToPort=port,
    )


@cli.command()
@click.argument("name")
@click.option("--user", default="ec2-user")
@click.option("--port", default=22, type=int)
def ssh(name, user, port):
    # security_group = None
    try:
        instance_id = get_instance_id(name)

        public_ip = get_instance_details(
            instance_id, "NetworkInterfaces/0/Association/PublicIp"
        )

        if not check_instance_open(instance_id, port):
            click.echo("Instance is not open")
            if check_ssm_plugin():
                port = 2222
                public_ip = "localhost"
                start_port_forward(instance_id, 22, 2222)
            else:
                raise NotImplementedError("Need to open security group")
                # port = 22
                # public_ip = get_instance_details(
                #     instance_id, "VpcId"
                # )

                # allow_port()

        # if not check_ssh_key(get_instance_details(instance_id, "KeyName")):
        #     click.echo("No matching ssh key")
        #     return
        command = f"ssh {user}@{public_ip}"
        if port:
            command = f"{command} -p {port}"
        subprocess.run(command, shell=True)
    finally:
        click.echo(f"Killing process {process.pid}")
        process.kill()


@cli.command()
@click.argument("name")
def ip(name):
    for n in get_instance_details(
        get_instance_id(name), "NetworkInterfaces/*", multiple=True
    ):
        click.echo(f'{n["Association"]["PublicIp"]} - {n["PrivateIpAddress"]}')


@cli.command()
@click.argument("name")
@click.option("--port")
@click.option("--local_port")
def port_forward(name, port=None, local_port=None):
    if name in PRESETS:
        port = PRESETS[name]["port"]
        name = PRESETS[name]["name"]

    assert check_ssm_plugin(), "SSM Plugin is required to port forward"
    assert port, "Port number is required"

    if port and local_port is None:
        if port < 1024:
            if port < 100:
                local_port = int(f"{port}{port}")
            else:
                local_port = int(f"10{port}")
        else:
            local_port = port

    assert local_port > 1024

    # webbrowser.open(f"http://localhost:{local_port}/")
    start_port_forward(get_instance_id(name), port, local_port)


# def plsql(name: str):
#     psql
#     f'psql "host={host} port=5432 sslmode=verify-full sslrootcert=/sample_dir/rds-combined-ca-bundle.pem dbname=DBName user=jane_doe"'

if __name__ == "__main__":
    cli()
