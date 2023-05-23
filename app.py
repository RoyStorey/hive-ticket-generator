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
from dash.exceptions import PreventUpdate

HOST_IP = ''
HOST_PORT = ''


csv_data = {
    'src_ip_list': [],
    'src_port_list': [],
    'dst_ip_list': [],
    'dst_port_list': [],
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
UPLOAD_FOLDER_ROOT = 'upload/'

hashes = {}

app = Dash(__name__, external_stylesheets=[
           '/assets/global.css'], prevent_initial_callbacks=True)

du.configure_upload(app, UPLOAD_FOLDER_ROOT, use_upload_id='')

app.layout = html.Div(id='content-container', className='content-container background', children=[
    html.Div(className='input-container', children=[
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
        html.Div(className='upload-div', children=[
            du.Upload(
                text='Click here or Drag a .csv file to upload',
                id='csv-upload',
                upload_id=None,
                filetypes=['csv']
            ),
        ]),
        html.Div(className='upload-div', children=[
            du.Upload(
                text='Click or Drag an Observable to upload',
                upload_id=None,
                max_files=10,
                id='observable-upload'
            ),
        ]),
        html.Div(className='buttons-wrapper', children=[
            html.Button('Format!', id='submit-button', n_clicks=0),
        ])
    ]),
    html.Div(className='output-container', children=[
        html.Div(id='formatted-output'),
        html.Div(id='callback-output-1'),
        html.Div(id='callback-output-2'),
        html.Div(id='callback-output-3'),
        dcc.Location(id='url', refresh=False)
    ]),
], style={'height': '100vh'})


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
                    src_ip, src_port, dst_ip, dst_port, community_id = row
                    csv_data['src_ip_list'].append(src_ip)
                    csv_data['src_port_list'].append(src_port)
                    csv_data['dst_ip_list'].append(dst_ip)
                    csv_data['dst_port_list'].append(dst_port)
                    csv_data['community_id_list'].append(community_id)
                file.close()
                os.remove(filename[0])
        except Exception as e:
            os.remove(filename[0])
            return dbc.Alert(e)


@du.callback(
    output=Output('callback-output-2', 'children'),
    id='observable-upload',
)
def hash_observables(status: du.UploadStatus):
    if status.is_completed:
        files = os.listdir('upload/')
        try:
            for file in files:
                with open(os.path.join('upload', file), 'rb') as f:
                    data = f.read()
                    sha256 = hashlib.sha256(data).hexdigest()
                    hashes[file] = sha256
                os.remove(os.path.join('upload', file))
        except Exception as e:
            for file in files:
                os.remove(os.path.join('upload', file))


def get_current_time():
    now = datetime.now()
    return now


@app.callback(
    Output('formatted-output', 'children'),
    State('initials-input', 'value'),
    State('attack-vector-input', 'value'),
    State('alert-input', 'value'),
    State('description-input', 'value'),
    State('remediation-input', 'value'),
    Input('submit-button', 'n_clicks'),
    Input('url', 'pathname')  # Add this line
)
def update_output(initials, attack_vector, alerts, description, remediation, n_clicks, url):
    if n_clicks > 0:
        try:

            # removes all duplicates from the dict
            for key, value in csv_data.items():
                csv_data[key] = list(set(value))
            hash_list = ["{} : {}".format(key, value)
                         for key, value in hashes.items()]
            string_hash = "\n".join(hash_list)
            return dcc.Textarea(
                id='output-textarea',
                className='output-textarea',
                value=f'**Time Observed:** {get_current_time()} by: {initials}\n\n**Src IP:** {str(csv_data["src_ip_list"])}\n\n**Src Ports:** {str(csv_data["src_port_list"])}\n\n**Dst IP:** {str(csv_data["dst_ip_list"])}\n\n**Dst Ports:** {str(csv_data["dst_port_list"])}\n\n**Community IDs:**\n{[str(x) for x in csv_data["community_id_list"]]}\n\n**Observable Hashes:**\n{string_hash}\n\n**MITRE Vectors of Attack:**\n{attack_vector}\n\n**Suricata Alerts:**\n{alerts}\n\n**Description:**\n{description}\n\n**Recommended Remediation:**\n{remediation}',
                style={'display': 'block', 'overflowY': 'auto'}
            ), hashes.clear(), csv_data.clear()
        except Exception as e:
            print(e)


if __name__ == '__main__':
    # app.run_server(port='8050',host='172.16.220.110')
    app.run_server(debug=True)
