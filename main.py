import joblib
from feature_new import FeatureExtraction
import numpy as np

# Load the model from the file


# url = "https://www.google.com"
# url = "http://drop-box-roug9779888876n1a2b3c4d5e6f7g8h9i0jk1l2m3n4o5p6q7r8s9t.vercel.app/	"
# url= "http://www.myjio-offr.xyz/on/"
# Create an instance of FeatureExtraction with the new URL
def main_function(url):
    filepath = ""
    try:
            
        model = joblib.load('model_Phishing_1.pkl')

        fe = FeatureExtraction(url)
        features = fe.getFeaturesList()
        print(features)
        filepath = fe.write_report(url)

        features_array = np.array(features).reshape(1, -1)

        # Predict the class (1 for phishing, 0 for legitimate)
        prediction = model.predict(features_array)

            # Get prediction probabilities if needed
        probabilities = model.predict_proba(features_array)
        print(probabilities)

        if prediction[0] == -1:
            result = f"The URL is likely a phishing URL."
        elif features.count(-1) >10:
            result = "The URL is likely a phishing URL.."
        else:
            result = "The URL is Safe."
        return result, url, filepath
    except Exception as e:
        result = f"Error occured {e}"
        return result, url, filepath