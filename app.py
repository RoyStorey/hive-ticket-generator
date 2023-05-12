from datetime import datetime
import csv
import glob
import hashlib
import base64
import datetime
import io
import pandas as pd
from dash import Dash, html, dcc, callback, Output, Input, dash_table
from dash.dependencies import Input, Output, State


app = Dash(__name__, external_stylesheets=['/assets/global.css'])

app.layout = html.Div(className='content-container', children=[
    html.Div(children=[
        html.Div(className='form-container', children=[
            html.Div(className='form-gap', children=[
                html.Label('Operator Initials:'),
                dcc.Input(id='initials-input'),
            ]),
            html.Div(className='form-gap', children=[
                html.Label('IDs:'),
                dcc.Textarea(id='id-input'),
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
            dcc.Upload(
                id='pcap-upload',
                children=html.Div([
                    'Drag and Drop .CSV or ',
                    html.A('Select .CSV file')
                ]),
                className='upload-div',
                style={
                    'width': '100%',
                    'height': '60px',
                    'lineHeight': '60px',
                    'borderWidth': '1px',
                    'borderStyle': 'dashed',
                    # 'borderRadius': '5px',
                    'textAlign': 'center',
                    # 'margin': '10px'
                },
                # Allow multiple files to be uploaded
            ),
            html.Div(id='output-data-upload')
        ]),
        html.Div([
            dcc.Upload(
                id='observable-upload',
                children=html.Div([
                    'Drag and Drop Observables or ',
                    html.A('Select Observables files')
                ]),
                className='upload-div',
                style={
                    # 'width': '100%',
                    'height': '60px',
                    'lineHeight': '60px',
                    'borderWidth': '1px',
                    'borderStyle': 'dashed',
                    # 'borderRadius': '5px',
                    'textAlign': 'center',
                    'margin-top': '10px'
                },
                # Allow multiple files to be uploaded
                multiple=True
            ),
        ]),
        html.Button('Format!', id='submit-button', n_clicks=0),
    ]),
    html.Div( className='output-container',children=[
        html.Div(id='formatted_output')
    ]),
])


@app.callback(
    Output('formatted_output', 'children'),
    Input('pcap-upload', 'contents'),
    Input('observable-upload', 'contents'),
    Input('initials-input', 'value'),
    Input('id-input', 'value'),
    Input('attack-vector-input', 'value'),
    Input('alert-input', 'value'),
    Input('description-input', 'value'),
    Input('solution-input', 'value'),
    Input('submit-button', 'n_clicks')

)
def update_output(pcap_contents, observable_contents, initials, ids, attack_vector, alerts, description, solution, n_clicks):
    if n_clicks > 0:
        return html.Div(f'pcap = {pcap_contents}, observable={observable_contents}, initials={initials}, id={ids}, vector={attack_vector}, alert={alerts}, description={description}, solution={solution}')


filenames = glob.glob("./case-files/*")
filehashes = []

i = 1
for filename in filenames:
    with open(filename, 'rb') as inputfile:
        data = inputfile.read()
        with open('hashedfiles', 'a') as file:
            file.write(hashlib.md5(data).hexdigest() + '\n')
            filehashes.append(' ' + str(i) + '. ' +
                              hashlib.md5(data).hexdigest())
            i = i+1


dataFile = open(r"sessions.csv")
dataFromCSV = csv.reader(dataFile, delimiter=',', skipinitialspace=True)
j = 1
SrcIP, DstIP, SrcPorts, DstPorts, CommIDs = [], [], [], [], []
next(dataFromCSV)
for row in dataFromCSV:
    if ' ' + row[2] not in SrcIP:
        SrcIP.append(' ' + row[2])
    if ' ' + row[4] not in SrcPorts:
        SrcPorts.append(' ' + row[4])
    if ' ' + row[5] not in DstIP:
        DstIP.append(' ' + row[5])
    if ' ' + row[7] not in DstPorts:
        DstPorts.append(' ' + row[7])
    if str(j) + '. ' + row[9] not in CommIDs:
        CommIDs.append(str(j) + '. ' + row[9])
        j = j+1


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
    app.run_server(debug=False)
