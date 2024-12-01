# FFC App 

## Setup

For installing an python env the application uses Anaconda. 

For creating a new env use:

`conda env create -f conda-env.yaml `

For updating the conda env in case the requirements.txt changed

`conda env update -f conda-env.yaml --prune`

Activate the conda env:

`conda activate ffc-app`

Initialize the database:

`python init_db.py`

Start the App:

`python run.py`