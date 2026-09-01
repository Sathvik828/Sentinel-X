from transformers import pipeline


MODEL_NAME = "ElSlay/BERT-Phishing-Email-Model"


_classifier = None


def load_model():

    global _classifier

    if _classifier is None:

        _classifier = pipeline(
            "text-classification",
            model=MODEL_NAME
        )

    return _classifier


def analyze_with_ai(text):

    text = str(text or "").strip()


    if not text:

        return {
            "label": "UNKNOWN",
            "confidence": 0.0,
            "phishing_probability": 0.0
        }


    text = text[:4000]


    try:

        classifier = load_model()


        result = classifier(
            text,
            truncation=True
        )[0]


        raw_label = str(
            result["label"]
        ).lower()


        confidence = float(
            result["score"]
        )


        if (
            "phish" in raw_label
            or raw_label in [
                "label_1",
                "1"
            ]
        ):

            label = "PHISHING"

            phishing_probability = (
                confidence
            )

        else:

            label = "LEGITIMATE"

            phishing_probability = (
                1.0 - confidence
            )


        return {

            "label":
                label,

            "confidence":
                round(
                    confidence * 100,
                    2
                ),

            "phishing_probability":
                round(
                    phishing_probability * 100,
                    2
                )

        }


    except Exception as e:

        return {

            "label":
                "ERROR",

            "confidence":
                0.0,

            "phishing_probability":
                0.0,

            "error":
                str(e)

        }