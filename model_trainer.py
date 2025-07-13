import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import joblib

# Step 1: Load the Dataset
# We are using a well-known public dataset for spam detection.
# 'ham' means a safe email, 'spam' means a phishing/unwanted email.
print("Downloading the dataset...")
try:
    # This URL points to the raw data file on GitHub
    url = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
    sms_data = pd.read_csv(url, sep='\t', names=['label', 'message'])
    print("Dataset downloaded successfully.")
except Exception as e:
    print(f"Failed to download dataset. Error: {e}")
    exit()

# Step 2: Define the Machine Learning Pipeline
# A pipeline chains together multiple steps. Our pipeline will:
# 1. 'vectorizer': Convert the email text into numerical feature vectors.
# 2. 'classifier': Use a Naive Bayes classifier to learn from these vectors.
model_pipeline = Pipeline([
    ('vectorizer', CountVectorizer()),
    ('classifier', MultinomialNB())
])

# Step 3: Train the Model
print("Training the model...")
# We separate the data into the 'message' (the input, X) and the 'label' (the output, y)
X = sms_data['message']
y = sms_data['label']

# The 'fit' method starts the training process
model_pipeline.fit(X, y)
print("Model training completed.")

# Step 4: Save the Trained Model
# We save our trained pipeline to a file named 'phishing_model.pkl'.
# Our FastAPI app will load this file later to make predictions.
model_filename = 'phishing_model.pkl'
joblib.dump(model_pipeline, model_filename)

print(f"Model saved successfully as '{model_filename}'")

# Optional: Test the model with a few examples
print("\n--- Testing the trained model ---")
test_safe_email = ["Hi, team. Let's meet tomorrow at 10 AM to discuss the project status. Thanks."]
test_phishing_email = ["Congratulations! You have won a $1000 Walmart gift card. Click here to claim now."]

prediction_safe = model_pipeline.predict(test_safe_email)
prediction_phishing = model_pipeline.predict(test_phishing_email)

print(f"Prediction for safe email: {prediction_safe[0]}") # Expected: ham
print(f"Prediction for phishing email: {prediction_phishing[0]}") # Expected: spam