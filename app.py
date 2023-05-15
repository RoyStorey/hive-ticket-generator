from datetime import datetime
import random
import csv
import hashlib
import os
import glob
from dash import Dash, html, dcc, Output, Input
import dash_bootstrap_components as dbc
import dash_uploader as du
from dash.dependencies import Input, Output, State
csv_data = {
    'start_list': [],
    'stop_list': [],
    'src_ip_list': [],
    'src_country_list': [],
    'src_port_list': [],
    'dst_ip_list': [],
    'dst_country_list': [],
    'dst_port_list': [],
    'uri_list': [],
    'community_id_list': []
}
formatted_csv_data = []
format_information = {
    'timeObserved': '',
    'initials': '',
    'sourceIP': '',
    'sourcePorts': '',
    'destinationIP': '',
    'destinationPorts': '',
    'communityIds': '',
    'ids': '',
    'observableHashes': '',
    'mitreVectors': '',
    'suricataAlerts': '',
    'description': '',
    'recommendedSolution': '',
}
hashes = {}
UPLOAD_FOLDER_ROOT = 'upload/'

app = Dash(__name__, external_stylesheets=[
           '/assets/global.css'], prevent_initial_callbacks=True)

du.configure_upload(app, UPLOAD_FOLDER_ROOT, use_upload_id='')

app.layout = html.Div(id='content-container', className='content-container', children=[
    html.Div(children=[
        html.Button('Change background!', id='background-button', n_clicks=0),
        html.Div(className='form-container', children=[
            html.Div(className='form-gap', children=[
                html.Label('Operator Initials:'),
                dcc.Input(id='initials-input'),
            ]),
            html.Div(className='form-gap', children=[
                html.Label('MITRE ATT&CK Vectors:'),
                dcc.Textarea(id='attack-vector-input'),
            ]),
            html.Div(className='form-gap', children=[
                html.Label('Suricata Alerts:'),
                dcc.Textarea(id='alert-input'),
            ]),
            html.Div(className='form-gap', children=[
                html.Label('Description:'),
                dcc.Textarea(id='description-input'),
            ]),
            html.Div(className='form-gap', children=[
                html.Label('Recommended Remediation:'),
                dcc.Textarea(id='remediation-input'),
            ]),
        ]),
        html.Div([
            du.Upload(
                text='Click here or Drag a .csv file to upload',
                id='csv-upload',
                upload_id=None,
                filetypes=['csv']
            ),
        ]),
        html.Div([
            du.Upload(
                text='Click or Drag an Observable to upload',
                upload_id=None,
                max_files=10,
                id='observable-upload',
            ),
        ]),
        html.Button('Format!', id='submit-button', n_clicks=0),
    ]),
    html.Div(className='output-container', children=[
        html.Div(id='formatted-output'),
        html.Div(id='callback-output-1'),
        html.Div(id='callback-output-2'),
        html.Div(id='callback-output-3'),
    ]),
], style={'height': '100vh', 'backgroundImage': 'url("./assets/bonkosphere.png', 'filter': 'hue-rotate(44deg)'})


@du.callback(
    output=Output('callback-output-1', 'children'),
    id='csv-upload'
)
def parse_csv(status: du.UploadStatus):
    if status.is_completed:
        try:
            filename = glob.glob('upload/*.csv')
            with open(filename[0], 'r') as file:
                reader = csv.reader(file)
                next(reader)
                for row in reader:
                    start_time, stop_time, src_ip, src_country, src_port, dst_ip, dst_country, dst_port, uri, community_id = row
                    csv_data['start_list'].append(start_time)
                    csv_data['stop_list'].append(stop_time)
                    csv_data['src_ip_list'].append(src_ip)
                    csv_data['src_country_list'].append(src_country)
                    csv_data['src_port_list'].append(src_port)
                    csv_data['dst_ip_list'].append(dst_ip)
                    csv_data['dst_country_list'].append(dst_country)
                    csv_data['dst_port_list'].append(dst_port)
                    csv_data['uri_list'].append(uri)
                    csv_data['community_id_list'].append(community_id)
                file.close()
                os.remove(filename[0])
        except Exception as e:
            return dbc.Alert(e)


@du.callback(
    output=Output('callback-output-2', 'children'),
    id='observable-upload'
)
def hash_observables(status: du.UploadStatus):
    if status.is_completed:
        files = os.listdir('upload/')
        for file in files:
            with open(file, 'rb') as f:
                data = f.read()
                sha256 = hashlib.sha256(data).hexdigest()
                hashes[file] = sha256
            os.remove(os.path.join('upload', file))


@app.callback(
    Output('formatted-output', 'children'),
    Input('initials-input', 'value'),
    Input('attack-vector-input', 'value'),
    Input('alert-input', 'value'),
    Input('description-input', 'value'),
    Input('remediation-input', 'value'),
    Input('submit-button', 'n_clicks')
)
def update_output(initials, attack_vector, alerts, description, remediation, n_clicks):
    if n_clicks > 0:

        # removes all duplicates from the dict
        for key, value in csv_data.items():
            csv_data[key] = list(set(value))
        hash_list = ["{} : {}".format(key, value)
                     for key, value in hashes.items()]
        string_hash = "\n".join(hash_list)
        return dcc.Textarea(
            value=f'**Time Observed:** by: {initials} \n\n**Src IP:** {str(csv_data["src_ip_list"])}\n\n**Src Ports:** {str(csv_data["src_port_list"])}\n\n**Dst IP:** {str(csv_data["dst_ip_list"])}\n\n**Dst Ports:** {str(csv_data["dst_port_list"])}\n\n**Community IDs:**\n{[str(x) for x in csv_data["community_id_list"]]}\n\n**Observable Hashes:**\n{string_hash}\n\n**MITRE Vectors of Attack:**\n{attack_vector}\n\n**Suricata Alerts:**\n{alerts}\n\n**Description:**\n{description}\n\n**Recommended Remediation:**\n{remediation}', style={'display': 'block', 'height': 650, 'width': 715, 'overflowY': 'auto'})


@app.callback(
    Output('content-container', 'style'),
    Input('background-button', 'n_clicks'),
    State('content-container', 'style')
)
def change_background(n_clicks, style):
    if n_clicks <= 0:
        return style
    hue = random.randint(1, 360)
    style['filter'] = f'hue-rotate({hue}deg)'
    return style


if __name__ == '__main__':
    app.run_server(debug=True)
