import json
import click
import requests
import validators


@click.group()
def command_manager():
    pass


@click.command()
@click.option("-u", "--url", type=str)
@click.option("-o", "--output_text", type=str)
@click.option("-j", "--output_json", type=str)
def url_scan(url, output_text, output_json):
    if not validators.url(url):
        click.echo(f"{url} is either Malformed or an Invalid URL")
        return

    api_call = f"http://127.0.0.1:8000/get_url_report?url={url}"
    r = requests.get(api_call).json()

    site_name = 'Undetected'
    if 'html_meta' in r['attributes']:
        if 'og:site_name' in r['attributes']['html_meta'] and r['attributes']['html_meta']['og:site_name'][0] is not None:
            site_name = r['attributes']['html_meta']['og:site_name'][0]
        elif 'og:title' in r['attributes']['html_meta'] and r['attributes']['html_meta'] is not None:
            site_name = r['attributes']['html_meta']['og:title'][0]

    if 'title' in r['attributes']:
        site_name = r['attributes']['title']

    try:
        site_trackers_list = list(r['attributes']['trackers'].keys())
        site_trackers_string = ', '.join(site_trackers_list)
    except Exception:
        site_trackers_string = 'Undetected'

    stats = r['attributes']['last_analysis_stats']

    click.echo(f"Site Name: {site_name}\n"
               f"URL:       {url}\n"
               f"Trackers:  {site_trackers_string}\n"
               f"Stats:     {stats}")

    if output_text is not None:
        with open(output_text, "w") as f:
            f.write(f"Site Name: {site_name}\n"
                    f"URL:       {url}\n"
                    f"Trackers:  {site_trackers_string}\n"
                    f"Stats:     {stats}")

    if output_json is not None:
        with open(output_json, "w") as f:
            json.dump(r, f)


@click.command()
@click.option("-f", "--file", type=str)
@click.option("-o", "--output_text", type=str)
@click.option("-j", "--output_json", type=str)
def file_scan(file, output_text, output_json):
    with open(file, "rb") as f:
        r = requests.post(f"http://127.0.0.1:8000/post_file_report", files={'file': f})
        f.close()

    r = requests.get('http://127.0.0.1:8000/get_file_report').json()

    file_type = r['attributes']['type_description']
    sha256_hash = r['attributes']['sha256']
    stats = r['attributes']['last_analysis_stats']

    click.echo(f"File Name:  {file}\n"
               f"File Type:  {file_type}\n"
               f"SHA-256:    {sha256_hash}\n"
               f"Stats:      {stats}")

    if output_text is not None:
        with open(output_text, "w") as f:
            f.write(f"File Name:  {file}\n"
                    f"File Type:  {file_type}\n"
                    f"SHA-256:    {sha256_hash}\n"
                    f"Stats:      {stats}")

    if output_json is not None:
        with open(output_json, "w") as f:
            json.dump(r, f)
            f.close()


command_manager.add_command(url_scan)
command_manager.add_command(file_scan)

if __name__ == "__main__":
    command_manager()
