
## About gdpr-analyzer
This tool allows the analysis of a website's compliance with the GDPR.
The purpose of the project is to use publicly available site data (source code) to write a nominal report and assign a compliance score. A scoring grid can be generated to understand the score obtained.

The tool is not intended to cover the entire GDPR. As stated above, only publicly available information will be analysed. As a result, not all information can be studied and the report can only rarely be exhaustive as to the use of data and the storage and protection methods put in place by the website owner
## Screnshot ??

## Installation
```bash
git clone https://git.scyde.fr/major-g9/gdpr-analyzer.git
```

## Recommended Python version
Gdpr-analyzer currently supports *Python 3*:
* The recommended version for Python 3 is 3.7.x

## Dependencies:
Gdpr-analyzer depends on the `bs4`, `argparse`, `mimetypes`, `requests`, `splinter`, `tinycss`, `platform`, `Jinja2` python modules.

These dependencies can be installed using the requirements file:
* Installation on Windows :
```
c:\python37\python.exe -m pip install -r requirements.txt
```
* Installation on Linux :
```bash
sudo pip install -r requirements.txt
```

Alternatively, each module can be installed independently.
## Usage

Short Form    | Long Form     | Description
------------- | ------------- |-------------
-f            | --full        | Get Full Analysis
-c            | --cookie      | Analyse the cookies and generate the score
-w            | --webbeacon   | Search the presence of web beacon and generate the score
-t            | --crypto      | Analyse the security of the connection with the website and generate the score
-r            | --report      | Generate a pdf report
-j            | --json        | Export the result in json

## Examples
To use all analysis options :

`python gdpr-analyser.py -f example.com`

To search the presence of web beacon and generate a pdf report :

`python gdpr-analyser.py -w -r example.com`

To analyse the security of the connection with the website and export the result in json :

`python gdpr-analyser.py -t -j example.com`

## Disclaimer
Accept any responsability or liability for the use of this anlysis tool. The usage of the product do not imply the responsibility of the **gdpr-analyzer** project.

The purpose of this tool is to provide an evaluation grid defined with our own criteria. However, if errors are brought to our attention it will be our care to correct them. Anyhow, the **gdpr-analyzer** project engage  any  responsibility  for the usage of the generated report.

It is not necessarily  complete,  accurate  and  updated.

It is our goal to minimise disruption caused by technical errors and we invite, therefore, the consumers to take all the possible preventive actions to avoid the problem. This disclaimer is not intended to avoid the obligations of the national laws, nor to exclude its liability for matters that may not be excluded under that law.

## License
Gdpr-analyzer is licensed under the GNU GPL v3.0. ??

cc : https://www.gnu.org/licenses/gpl-3.0.en.html

## Version
**Current version is 0.1**
