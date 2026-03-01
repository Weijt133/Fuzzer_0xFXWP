from config.config import FUZZER_CONFIG
import magic

class Recognizer:
    def __init__(self):
        self.config = FUZZER_CONFIG
        
    def recognize(self, input_path):
        with open(input_path, 'rb') as f:
            res = f.read()
        mime_type = magic.from_file(input_path, mime=True)
        if mime_type in self.config['mime_type_mapping']:
            type = self.config['mime_type_mapping'][mime_type]
            return (type, res)
        else:
            return ('plaintext', res)
        

if __name__ == "__main__":
    recognizer = Recognizer()
    sample_path = "test/example_inputs/plaintext2.txt"
    type = recognizer.recognize(sample_path)
    print(type)