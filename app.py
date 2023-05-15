from datetime import datetime
import csv
import hashlib
import os
import glob
from dash import Dash, html, dcc, Output, Input
import dash_bootstrap_components as dbc
import dash_uploader as du
from dash.dependencies import Input, Output
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
hashes = {}
UPLOAD_FOLDER_ROOT = 'upload/'

app = Dash(__name__, external_stylesheets=[
           '/assets/global.css'], prevent_initial_callbacks=True)

du.configure_upload(app, UPLOAD_FOLDER_ROOT, use_upload_id='')

app.layout = html.Div(className='content-container', children=[
    html.Div(children=[
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
                html.Label('Recommended Solution:'),
                dcc.Textarea(id='solution-input'),
            ]),
        ]),
        html.Div([
            du.Upload(
                text='Click here or Drag a .csv file to upload',
                id='csv-upload',
                upload_id=None,
                filetypes=['csv'],
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
        html.Div(id='callback-output-2')
    ]),
])


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
    Input('solution-input', 'value'),
    Input('submit-button', 'n_clicks')

)
def update_output(initials, attack_vector, alerts, description, solution, n_clicks):
    if n_clicks > 0:
        return dcc.Textarea(value=f'initials={initials}, vector={attack_vector}, alert={alerts}, description={description}, solution={solution},{str(hashes)}, {str(csv_data)}')


# filenames = glob.glob("./case-files/*")
# filehashes = []

# i = 1
# for filename in filenames:
#     with open(filename, 'rb') as inputfile:
#         data = inputfile.read()
#         with open('hashedfiles', 'a') as file:
#             file.write(hashlib.md5(data).hexdigest() + '\n')
#             filehashes.append(' ' + str(i) + '. ' +
#                               hashlib.md5(data).hexdigest())
#             i = i+1


# dataFile = open(r"sessions.csv")
# dataFromCSV = csv.reader(dataFile, delimiter=',', skipinitialspace=True)
# j = 1
# SrcIP, DstIP, SrcPorts, DstPorts, CommIDs = [], [], [], [], []
# next(dataFromCSV)
# for row in dataFromCSV:
#     if ' ' + row[2] not in SrcIP:
#         SrcIP.append(' ' + row[2])
#     if ' ' + row[4] not in SrcPorts:
#         SrcPorts.append(' ' + row[4])
#     if ' ' + row[5] not in DstIP:
#         DstIP.append(' ' + row[5])
#     if ' ' + row[7] not in DstPorts:
#         DstPorts.append(' ' + row[7])
#     if str(j) + '. ' + row[9] not in CommIDs:
#         CommIDs.append(str(j) + '. ' + row[9])
#         j = j+1


# now = datetime.now()
# dt_string = now.strftime("%m/%d/%Y %H:%M:%S")

# formattedHiveCase = 'test's


# class formattedHiveCase:
#     timeObserved = dt_string
#     initials = input('Operator Initials:\n')
#     sourceIP = ','.join(SrcIP)
#     sourcePorts = ','.join(SrcPorts)
#     destinationIP = ','.join(DstIP)
#     destinationPorts = ','.join(DstPorts)
#     communityIds = '\n'.join(CommIDs)
#     ids = input('IDs:\n')
#     observableHashes = '\n'.join(filehashes)
#     mitreVectors = input('MITRE ATT&CK Vectors:\n')
#     suricataAlerts = input('Suricata Alerts:\n')
#     description = input('Description:\n')
#     recommendedSolution = input('Recommended Solution:\n')


# print(formattedHiveCase)

# print("**Time Observed:** ", formattedHiveCase.timeObserved, "by " + formattedHiveCase.initials +  "\n\n**Src IP:** " + formattedHiveCase.sourceIP + "\n**Src Ports:** " + formattedHiveCase.sourcePorts + "\n\n**Dst IP:** " + formattedHiveCase.destinationIP + "\n**Dst Ports:** " + formattedHiveCase.destinationPorts + "\n\n**Community IDs:**\n" + formattedHiveCase.communityIds + "\n\n**IDs:**\n" + formattedHiveCase.ids + "\n\n**Observables/Hashes:**\n" + formattedHiveCase.observableHashes + "\n\n**MITRE Vectors of Attack** " + formattedHiveCase.mitreVectors + "\n\n**Suricata Alerts:** " + formattedHiveCase.suricataAlerts + "\n\n**Description:** " + formattedHiveCase.description + "\n\n**Recommended Solution:** " + formattedHiveCase.recommendedSolution)

if __name__ == '__main__':
    app.run_server(debug=True)
