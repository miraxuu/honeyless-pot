import pandas as pd
import re

def filter_and_add_features(input_file, output_file):
    """
    Filter the dataset for GET requests and add features including normalized special character counts.

    Args:
        input_file (str): Path to the input CSV file.
        output_file (str): Path to save the filtered dataset with added features.
    """
    # Load the dataset
    df = pd.read_csv(input_file)

    # Check if the required columns exist
    if 'method' not in df.columns or 'Query' not in df.columns:
        print("Error: The required columns ('method', 'Query') do not exist in the file.")
        return

    # Filter for GET requests
    df = df[df['method'].str.upper() == 'GET']

    # List of special characters to count
    special_chars = r'!@#$%^&*(),.?":{}|<>[];\'\\/~`+=-_'

    # Add general features
    df['query_length'] = df['Query'].apply(len)  # Length of the query
    df['num_url_encoded_chars'] = df['Query'].apply(lambda x: len(re.findall(r'%[0-9a-fA-F]{2}', x)))  # URL-encoded chars
    df['num_digits'] = df['Query'].apply(lambda x: len(re.findall(r'\d', x)))  # Number of digits
    df['num_uppercase'] = df['Query'].apply(lambda x: sum(1 for c in x if c.isupper()))  # Uppercase chars
    df['num_lowercase'] = df['Query'].apply(lambda x: sum(1 for c in x if c.islower()))  # Lowercase chars

    # Count special characters and normalize them
    for char in special_chars:
        # Raw count
        char_column = f'count_{repr(char)[1:-1]}'
        df[char_column] = df['Query'].apply(lambda x: x.count(char))
        # Normalized count (divide by query length to account for query size differences)
        normalized_column = f'normalized_{repr(char)[1:-1]}'
        df[normalized_column] = df[char_column] / df['query_length']

    # Save the filtered dataset with added features
    df.to_csv(output_file, index=False)
    print(f"Filtered GET requests with added features saved to {output_file}")

# Example usage
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Filter GET requests and add features to a CSV.")
    parser.add_argument("input_file", help="Path to the input CSV file.")
    parser.add_argument("output_file", help="Path to save the output CSV file with features.")
    args = parser.parse_args()

    filter_and_add_features(args.input_file, args.output_file)
