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

app.layout=html.Div( className='content-container', children=[
    html.Div(className='form-container', children=[
        html.Div(className='form-gap', children=[
            html.Label('Operator Initials:'),
            dcc.Input(id='Operator Initials:'),
        ]),
        html.Div(className='form-gap', children=[
            html.Label('IDs:'),
            dcc.Input(id='IDs:'),
        ]),
        html.Div(className='form-gap', children=[
            html.Label('MITRE ATT&CK Vectors:'),
            dcc.Input(id='MITRE ATT&CK Vectors:'),
        ]),
        html.Div(className='form-gap', children=[
            html.Label('Suricata Alerts:'),
            dcc.Input(id='Suricata Alerts:'),
        ]),
        html.Div(className='form-gap', children=[
            html.Label('Description:'),
            dcc.Input(id='Description:'),
        ]),
        html.Div(className='form-gap', children=[
            html.Label('Recommended Solution:'),
            dcc.Input(id='Recommended Solution:'),
        ]),
    ]),
        html.Div([
        dcc.Upload(
            id='upload_data',
            children=html.Div([
                'Drag and Drop .CSV or ',
                html.A('Select .CSV file')
            ]),
            style={
                'width': '100%',
                'height': '60px',
                'lineHeight': '60px',
                'borderWidth': '1px',
                'borderStyle': 'dashed',
                'borderRadius': '5px',
                'textAlign': 'center',
                # 'margin': '10px'
            },
            # Allow multiple files to be uploaded
        ),
        html.Div(id='output-data-upload')
    ]),
    html.Div([
        dcc.Upload(
            id='upload-data',
            children=html.Div([
                'Drag and Drop Observables or ',
                html.A('Select Observables files')
            ]),
            style={
                # 'width': '100%',
                'height': '60px',
                'lineHeight': '60px',
                'borderWidth': '1px',
                'borderStyle': 'dashed',
                'borderRadius': '5px',
                'textAlign': 'center',
                'margin-top': '10px'
            },
        # Allow multiple files to be uploaded
        multiple=True
    ),
]),
html.Button('submit'),
html.Div(id='formatted_output')
])

def parse_contents(contents, filename, date):
    content_type, content_string = contents.split(',')
    decoded = base64.b64decode(content_string)
    try:
        if 'csv' in filename:
            # Assume that the user uploaded a CSV file
            df = pd.read_csv(
                io.StringIO(decoded.decode('utf-8')))
        elif 'xls' in filename:
            # Assume that the user uploaded an excel file
            df = pd.read_excel(io.BytesIO(decoded))
    except Exception as e:
        print(e)
        return html.Div([
            'There was an error processing this file.'
        ])
    return html.Div([
        html.H5(filename),
        html.H6(datetime.datetime.fromtimestamp(date)),

        dash_table.DataTable(
            df.to_dict('records'),
            [{'name': i, 'id': i} for i in df.columns]
        ),

        html.Hr(),  # horizontal line

        # For debugging, display the raw contents provided by the web browser
        html.Div('Raw Content'),
        html.Pre(contents[0:200] + '...', style={
            'whiteSpace': 'pre-wrap',
            'wordBreak': 'break-all'
        })
    ])
    

@app.callback(
    Output('formatted_output','children'),
    Input('upload_data','contents'),
    # State('upload_data', 'filename'),
    # State('upload_data', 'last_modified')
)
def update_output(list_of_contents):
    if list_of_contents is not None:
        children = [
            parse_contents(c) for c in
            zip(list_of_contents)]
        return children
    


filenames = glob.glob("./case-files/*")
filehashes = []

i = 1
for filename in filenames:
    with open(filename, 'rb') as inputfile:
        data = inputfile.read()
        with open('hashedfiles','a') as file:
            file.write(hashlib.md5(data).hexdigest() + '\n')
            filehashes.append( ' ' + str(i) + '. ' + hashlib.md5(data).hexdigest())
            i = i+1



dataFile = open(r"sessions.csv")
dataFromCSV = csv.reader(dataFile,delimiter=',', skipinitialspace=True)
j = 1
SrcIP, DstIP, SrcPorts, DstPorts, CommIDs  = [], [], [], [], []
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