# Thesis

This project demonstrates the use of five post-quantum cryptographic algorithms in Python. Each algorithm folder includes two variations: **128-bit** and **256-bit** implementations.

## Setup Instructions

### 1. Install Python 3
Make sure you have Python 3 installed on your system.

### 2. Activate Virtual Environment (optional)
You can either use your own virtual environment or the one provided:

```bash
source venv/bin/activate
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install liboqs-python

Navigate to the `liboqs-python` folder and install it:

```bash
cd liboqs-python
pip install .
```

---

## Running the Scripts

To run an algorithm, follow these steps:

### 1. Create a New Folder

Inside the relevant algorithm and variant (e.g., `Falcon/128`), **create a new folder** where you will run your test.

```bash
mkdir mytest
cd mytest
```

### 2. Copy Required Files

- Copy the Python script (e.g., `falconaes128.py`) into the new folder.
- Copy the `city.xlsx` file into this folder as well.

```bash
cp ../falconaes128.py .
cp ../city.xlsx .
```

### 3. Run the Script

```bash
python falconaes128.py
```

This will process the data and generate output inside a `results/` folder.

---

## Generate Graphs

To visualize the results:

1. Copy the `allgraphs.py` file from the original `results/` folder:

```bash
cp ../results/allgraphs.py results/
```

2. Run the graphing script:

```bash
python results/allgraphs.py
```

This will generate plots based on your experiment results.
