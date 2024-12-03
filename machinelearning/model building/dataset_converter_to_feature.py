import pandas as pd
import re

def add_features_and_normalize_labeled(input_file, output_file):
    """
    Add features, including normalized special character counts, to the labeled dataset.

    Args:
        input_file (str): Path to the input CSV file.
        output_file (str): Path to save the dataset with added features.
    """
    # Load the dataset
    df = pd.read_csv(input_file)

    # Check if required columns exist
    if 'Query' not in df.columns or 'Label' not in df.columns:
        print("Error: The required columns 'Query' and 'Label' do not exist in the file.")
        return

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

    # Save the dataset with added features
    df.to_csv(output_file, index=False)
    print(f"Dataset with added features saved to {output_file}")

# Example Usage
input_file = "Modified_SQL_Dataset.csv"  # Replace with your input CSV file
output_file = "labeled_dataset_with_features.csv"  # Replace with your desired output file
add_features_and_normalize_labeled(input_file, output_file)
