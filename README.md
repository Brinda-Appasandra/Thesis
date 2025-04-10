# Thesis

## Environment Setup and Execution Workflow

## Introduction

This document details the necessary steps to configure the computational environment required to replicate the experiments presented in this project/thesis. The project utilizes Python 3 and related libraries for implementing and evaluating various post-quantum cryptographic (PQC) algorithms. Adherence to the following instructions will ensure a consistent setup for running the performance evaluation scripts and generating the corresponding results.

## Prerequisites

Before proceeding with the project setup, ensure the following software components are installed on your system:

1.  **Python 3:** The core programming language used for the implementation. Version 3.7 or higher is recommended. Installation instructions can be found on the official Python website ([https://www.python.org/](https://www.python.org/)). Verify the installation by opening a terminal or command prompt and running:
    ```bash
    python3 --version
    # or potentially:
    # python --version
    ```
2.  **Git:** A distributed version control system required to download (clone) the project source code from its repository. Installation details are available at [https://git-scm.com/](https://git-scm.com/). Verify the installation by running:
    ```bash
    git --version
    ```

## Setup Procedure

Follow these steps to download the project code and install the necessary dependencies:

1.  **Clone the Repository:** Open a terminal or command prompt and navigate to the directory where you wish to store the project. Execute the following command to download the source code from the specified URL:
    ```bash
    git clone https://github.com/Brinda-Appasandra/Thesis
    ```
    This command creates a new directory named `Thesis` containing the project files.

2.  **Navigate to Project Directory:** Change your current directory to the newly cloned project folder:
    ```bash
    cd Thesis
    ```

3.  **Create a Virtual Environment:** It is highly recommended to use a virtual environment to isolate project dependencies. Create one using Python's built-in `venv` module:
    ```bash
    python3 -m venv venv
    ```
    This creates a sub-directory named `venv` containing a private Python installation.

4.  **Activate the Virtual Environment:** Activate the environment to ensure subsequent package installations are contained within it.
    *   On **macOS and Linux**:
        ```bash
        source venv/bin/activate
        ```
    *   On **Windows**:
        ```bash
        .\venv\Scripts\activate
        ```
    Your terminal prompt should change, often prepended with `(venv)`, indicating the virtual environment is active.

5.  **Install Python Dependencies:** Install the required Python libraries using requirements.txt. A crucial dependency is `liboqs-python`.
    *   *For Python libraries*
        ```bash
        pip install -r requirements.txt
        ```
    *   * Install `liboqs-python` specifically by using below commands):*
        ```bash
        cd liboqs-python
        pip install .
        ```

## Execution Workflow

Once the environment is set up, follow these steps to run the cryptographic algorithm evaluations and generate performance graphs:

1.  **Select an Algorithm:** Navigate into the directory corresponding to the specific PQC algorithm and variant you wish to evaluate. For example, to test the 128-bit Falcon implementation:
    ```bash
    cd Falcon/Falcon-128
    ```

2.  **Prepare Input Data:** Copy the data file intended for encryption/signing into the current algorithm directory. The reference uses `city.xlsx` as an example. Place your data file (e.g., `city.xlsx`) in this directory. If copying from elsewhere:
    ```bash
    # Example: copy city.xlsx into the current directory
    cp /path/to/your/data/city.xlsx .
    ```
    *(Replace `/path/to/your/data/city.xlsx` with the actual path to your data file).*

3.  **Run the Evaluation Script:** Execute the Python script associated with the chosen algorithm using Python 3. Using the Falcon-128 example:
    ```bash
    python3 falconaes128.py
    ```
    *(Replace `falconaes128.py` with the correct script name for the chosen algorithm if it differs).*

4.  **Observe Generated Artifacts:** Upon successful execution, check the algorithm directory (e.g., `Falcon/Falcon-128`). Several sub-directories should have been created:
    *   `Keys/`: Contains the generated public and private key pairs.
    *   `Encrypted/`: Contains the encrypted versions of the input data file(s).
    *   `Decrypted/`: Contains the decrypted files (should match the original input data).
    *   `Signed/`: Contains the digital signatures generated for the input data file(s).
    *   `Results/`: Contains a `computation_times.csv` file logging performance metrics.

5.  **Generate Performance Graphs:** To visualize the results:
    *   **Copy Graphing Script:** Copy the `allgraphs.py` script from the repository root into the `Results/` directory generated in the previous step. Assuming you are still in the algorithm directory (e.g., `Falcon/Falcon-128`):
        ```bash
        # Adjust path ../../ if needed based on your PWD relative to repository root
        cp ../../allgraphs.py Results/
        ```
    *   **Navigate to Results Directory:**
        ```bash
        cd Results
        ```
    *   **Run Graphing Script:** Execute the script using Python 3:
        ```bash
        python3 allgraphs.py
        ```

6.  **View Generated Graphs:** The execution of `allgraphs.py` will generate various plot files (e.g., `.png`, `.csv`) within the `Results/` directory, visually representing the computational performance data from the `.csv` file.

## Conclusion

By following the steps outlined above, the experimental environment can be successfully configured, the PQC algorithm evaluations can be executed, and the performance results can be generated and visualized. This provides a reproducible framework for analysing the algorithms.

Remember to deactivate the virtual environment when you are finished working on the project:
```bash
deactivate
