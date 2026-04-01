import os                          # Import the os module for interacting with the operating system
import logging                     # Import logging to record messages to a log file
from PIL import Image              # Import the Image class from PIL (Pillow) for image processing
import numpy as np                 # Import numpy as np for numerical operations on image arrays

# Setup logging to a file named 'analysis_log.txt', with INFO level and a standard message format
logging.basicConfig(
    filename='analysis_log.txt',   # Log file name
    level=logging.INFO,            # Log level set to INFO
    format='%(asctime)s %(levelname)s:%(message)s'  # Log message format: timestamp, level, message
)

def read_text_file(filepath):
    """
    Safely reads a text file, handling exceptions.
    """
    try:
        # Try to open the file at the given path in read mode
        with open(filepath, 'r') as f:
            data = f.read()              # Read all content from the file into a string
        logging.info(f"Successfully read text file: {filepath}")  # Log successful read
        return data                      # Return the string data
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")   # Log if the file does not exist
    except Exception as e:
        logging.error(f"Error reading {filepath}: {str(e)}")  # Log any other exceptions
    return None                          # Return None if reading failed

def analyze_image(filepath):
    """
    Extract pixels and compute statistics from an image using PIL.
    """
    try:
        # Try to open the image file at the given path
        with Image.open(filepath) as img:
            img_array = np.array(img)        # Convert the image to a numpy array for analysis
            max_pixel = np.max(img_array)    # Find the maximum pixel value in the array
            mean_pixel = np.mean(img_array)  # Compute the mean (average) of all pixel values
            logging.info(
                f"Image: {filepath} | Max Pixel Value: {max_pixel} | Mean Pixel Value: {mean_pixel:.2f}"
            )                               # Log the computed statistics
            return {
                'max_pixel': max_pixel,      # Return max pixel value in a dictionary
                'mean_pixel': mean_pixel,    # Return mean pixel value in the same dictionary
            }
    except FileNotFoundError:
        logging.error(f"Image not found: {filepath}")  # Log if the image file is missing
    except Exception as e:
        logging.error(f"Error processing image {filepath}: {str(e)}")  # Log any image processing errors
    return None                              # Return None if processing failed

def main():
    # Example file paths for text and image
    text_path = 'example.txt'                # Path to the text file to read
    image_path = 'example.jpg'               # Path to the image file to analyze
    
    # Read text data from disk
    text_data = read_text_file(text_path)    # Call function to read text file
    
    # Analyze the image file for pixel statistics
    img_stats = analyze_image(image_path)    # Call function to analyze the image
    
    # Optional: Print whether text file loaded successfully
    print(f"Text file loaded: {text_data is not None}")   # Print status of text file loading
    # Optional: Print the analysis result of the image
    print(f"Image analysis result: {img_stats}")          # Print image statistics (dict or None)

# Check if this script is being run directly
if __name__ == "__main__":
    main()                                   # Call the main function if script is executed directly
