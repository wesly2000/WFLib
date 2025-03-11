import numpy as np
import os
import random
import argparse
from sklearn.model_selection import train_test_split

# Set a fixed seed for reproducibility
fix_seed = 2024
random.seed(fix_seed)
np.random.seed(fix_seed)

# Set up argument parser to get dataset name from command line arguments
parser = argparse.ArgumentParser(description="WFlib")
parser.add_argument("--dataset", type=str, required=True, default="Undefended", help="Dataset name")
parser.add_argument("--use_stratify", type=str, default="True", help="Whether to use stratify")
parser.add_argument("-f", "--feature", type=str, default="X", help="The name of features to use")
parser.add_argument("-s", "--train_size", type=float, default=0.9, help="The train_size of training dataset")
parser.add_argument("-o", "--output_dir", type=str, help="The output dir, if not given, the param dataset is used as default")

# Parse arguments
args = parser.parse_args()
infile = os.path.join("./datasets", f"{args.dataset}.npz")
if args.output_dir:
    dataset_path = os.path.join("./datasets", args.output_dir)
else:
    dataset_path = os.path.join("./datasets", args.dataset)
os.makedirs(dataset_path, exist_ok=True)

assert os.path.exists(infile), f"{infile} does not exist!"

# Load dataset from the specified .npz file
print("loading...", infile)
data = np.load(infile)
X = data[args.feature]
try:
    y = data["y"]
except KeyError:
    try:
        y = data["label"]
    except KeyError:
        y = data["labels"]

# Ensure labels are continuous
num_classes = len(np.unique(y))
assert num_classes == y.max() + 1, "Labels are not continuous"


if args.use_stratify == "True":
    X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=args.train_size, random_state=fix_seed, stratify=y)
    X_train, X_valid, y_train, y_valid = train_test_split(X_train, y_train, train_size=args.train_size, random_state=fix_seed, stratify=y_train)
else:
    X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=args.train_size, random_state=fix_seed)
    X_train, X_valid, y_train, y_valid = train_test_split(X_train, y_train, train_size=args.train_size, random_state=fix_seed)

# Print dataset information
print(f"Train: X = {X_train.shape}, y = {y_train.shape}")
print(f"Valid: X = {X_valid.shape}, y = {y_valid.shape}")
print(f"Test: X = {X_test.shape}, y = {y_test.shape}")

# Save the split datasets into separate .npz files
np.savez(os.path.join(dataset_path, "train.npz"), X = X_train, y = y_train)
np.savez(os.path.join(dataset_path, "valid.npz"), X = X_valid, y = y_valid)
np.savez(os.path.join(dataset_path, "test.npz"), X = X_test, y = y_test)