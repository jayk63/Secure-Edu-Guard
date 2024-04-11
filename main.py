# Import necessary libraries
import mysql.connector  # Database library
import pandas as pd  # Data manipulation library
import streamlit as st  # GUI library
from streamlit_option_menu import option_menu  # GUI utility library
from sklearn.linear_model import LinearRegression  # Machine Learning library
import base64  # Encoding library
from paillier import Paillier  # Homomorphic encryption library
from phe import paillier  # Alternative homomorphic encryption library
import streamlit as st
import pefile
import os
import array
import math
import pickle
import joblib
import tempfile
import pandas as pd


def malware():
    def get_entropy(data):
        if len(data) == 0:
            return 0.0
        occurences = array.array('L', [0]*256)
        for x in data:
            occurences[x if isinstance(x, int) else ord(x)] += 1

        entropy = 0
        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x*math.log(p_x, 2)

        return entropy

    def get_resources(pe):
        """Extract resources :
        [entropy, size]"""
        resources = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            try:
                    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                        if hasattr(resource_type, 'directory'):
                            for resource_id in resource_type.directory.entries:
                                if hasattr(resource_id, 'directory'):
                                    for resource_lang in resource_id.directory.entries:
                                        data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                        size = resource_lang.data.struct.Size
                                        entropy = get_entropy(data)

                                        resources.append([entropy, size])
            except Exception as e:
                return resources
        return resources

    def get_version_info(pe):
        """Return version infos"""
        res = {}
        for fileinfo in pe.FileInfo:
            if fileinfo.Key == 'StringFileInfo':
                for st in fileinfo.StringTable:
                    for entry in st.entries.items():
                        res[entry[0]] = entry[1]
            if fileinfo.Key == 'VarFileInfo':
                for var in fileinfo.Var:
                    res[var.entry.items()[0][0]] = var.entry.items()[0][1]
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
            res['os'] = pe.VS_FIXEDFILEINFO.FileOS
            res['type'] = pe.VS_FIXEDFILEINFO.FileType
            res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
            res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
            res['signature'] = pe.VS_FIXEDFILEINFO.Signature
            res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
        return res

    #extract the info for a given file
    def extract_infos(fpath):
        res = {}
        pe = pefile.PE(fpath)
        res['Machine'] = pe.FILE_HEADER.Machine
        res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        res['Characteristics'] = pe.FILE_HEADER.Characteristics
        res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        try:
            res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
        except AttributeError:
            res['BaseOfData'] = 0
        res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
        res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
        res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

        # Sections
        res['SectionsNb'] = len(pe.sections)
        entropy =list(map(lambda x:x.get_entropy(), pe.sections))
        res['SectionsMeanEntropy'] = sum(entropy)/float(len(entropy))
        res['SectionsMinEntropy'] = min(entropy)
        res['SectionsMaxEntropy'] = max(entropy)
        raw_sizes =list(map(lambda x:x.SizeOfRawData, pe.sections))
        res['SectionsMeanRawsize'] = sum(raw_sizes)/float(len(raw_sizes))
        res['SectionsMinRawsize'] = min(raw_sizes)
        res['SectionsMaxRawsize'] = max(raw_sizes)
        virtual_sizes =list(map(lambda x:x.Misc_VirtualSize, pe.sections))
        res['SectionsMeanVirtualsize'] = sum(virtual_sizes)/float(len(virtual_sizes))
        res['SectionsMinVirtualsize'] = min(virtual_sizes)
        res['SectionMaxVirtualsize'] = max(virtual_sizes)

        #Imports
        try:
            res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
            res['ImportsNb'] = len(imports)
            res['ImportsNbOrdinal'] = 0
        except AttributeError:
            res['ImportsNbDLL'] = 0
            res['ImportsNb'] = 0
            res['ImportsNbOrdinal'] = 0

        #Exports
        try:
            res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except AttributeError:
            # No export
            res['ExportNb'] = 0
        #Resources
        resources= get_resources(pe)
        res['ResourcesNb'] = len(resources)
        if len(resources)> 0:
            entropy = list(map(lambda x:x[0], resources))
            res['ResourcesMeanEntropy'] = sum(entropy)/float(len(entropy))
            res['ResourcesMinEntropy'] = min(entropy)
            res['ResourcesMaxEntropy'] = max(entropy)
            sizes = list(map(lambda x:x[1], resources))
            res['ResourcesMeanSize'] = sum(sizes)/float(len(sizes))
            res['ResourcesMinSize'] = min(sizes)
            res['ResourcesMaxSize'] = max(sizes)
        else:
            res['ResourcesNb'] = 0
            res['ResourcesMeanEntropy'] = 0
            res['ResourcesMinEntropy'] = 0
            res['ResourcesMaxEntropy'] = 0
            res['ResourcesMeanSize'] = 0
            res['ResourcesMinSize'] = 0
            res['ResourcesMaxSize'] = 0

        # Load configuration size
        try:
            res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        except AttributeError:
            res['LoadConfigurationSize'] = 0


        # Version configuration size
        try:
            version_infos = get_version_info(pe)
            res['VersionInformationSize'] = len(version_infos.keys())
        except AttributeError:
            res['VersionInformationSize'] = 0
        return res
        
    #new_title = '<p style="font-family:sans-serif; color:White; font-size: 40px;">Malware Detection Using Machine Learning</p>'
    #st.markdown(new_title, unsafe_allow_html=True)

    uploaded_file = st.file_uploader("Choose a zip file")
    if uploaded_file is None:
        st.text("Please upload the path")
    if uploaded_file is not None:
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.write(uploaded_file.read())
        temp_file.close()
        file_path = temp_file.name
        @st.cache_data()
        def load_model():
            clf = joblib.load('classifier.pkl')
            return clf

        def load_features():
            features = pickle.loads(open(os.path.join('features.pkl'),'rb').read())
            return features
        with st.spinner('Model is being loaded..'):
            clf=load_model()
        with st.spinner('Features are been loading'):
            features=load_features()
        
        if st.button("Predict"):
            data = extract_infos(file_path)
            pe_features =list(map(lambda x:data[x], features))
            st.text(pe_features)
            res= clf.predict([pe_features])[0]
            df = pd.DataFrame([data])
            dft=df.transpose()
            dft.columns=['Feature_Value']
            st.table(dft)
            t='The file %s is %s' % (os.path.basename(uploaded_file.name),['legitimate','malicious'][res])
            new_title = '<p style="font-family:sans-serif;font-size: 30px;">{}</p>'.format(t)
            st.markdown(new_title, unsafe_allow_html=True)

db = st.connection('mysql', type='sql')
'''
db = mysql.connector.connect(
    host="localhost", user="root", password="Planet@123"
)
'''
# Create a new database if it doesn't exist
cursor = db.cursor()
cursor.execute("CREATE DATABASE IF NOT EXISTS mydatabase")
print("Database created successfully")
'''
# Connect to the new database
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password= "Planet@123",
    database="mydatabase",
)
'''
cursor = db.cursor()
print("Database Connected")

# Set page configuration
st.set_page_config(
    page_title="Homepage",
    page_icon="🔐",
)

# Instantiate the Paillier cryptosystem
p = Paillier()

# Generate public and private keys
public_key, private_key = paillier.generate_paillier_keypair()


def encrypt_number(n, pk):
    return pk.encrypt(n)


def decrypt_number(c, sk):
    return sk.decrypt(c)


def encode_string(s):
    return base64.b64encode(s.encode()).decode()


def decode_string(s):
    return base64.b64decode(s.encode()).decode()


def IT():
    with st.form(key="it"):
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS Encrypted (
                id INT AUTO_INCREMENT PRIMARY KEY,
                Name VARCHAR(255),
                `Roll no` VARCHAR(255),
                Course VARCHAR(255),
                `Sem/Year` VARCHAR(255),
                DMBI VARCHAR(255),
                `Web-X` VARCHAR(255),
                WT VARCHAR(255),
                AI VARCHAR(255),
                GIT VARCHAR(255),
                Total VARCHAR(255),
                Average VARCHAR(255),
                `Percentage %` VARCHAR(255)
            )"""
        )

        cursor.execute(
            """CREATE TABLE IF NOT EXISTS Decrypted (
                id INT AUTO_INCREMENT PRIMARY KEY,
                Name VARCHAR(255),
                `Roll no` VARCHAR(255),
                Course VARCHAR(255),
                `Sem/Year` VARCHAR(255),
                DMBI VARCHAR(255),
                `Web-X` VARCHAR(255),
                WT VARCHAR(255),
                AI VARCHAR(255),
                GIT VARCHAR(255),
                Total VARCHAR(255),
                Average VARCHAR(255),
                `Percentage %` VARCHAR(255)
            )"""
        )
        print("IT Tables created successfully")

        marks = []
        DMBI = st.number_input(
            f"Enter marks for Data Mining & Business Intelligence (DMBI)",
            min_value=1,
            max_value=100,
        )
        marks.append(DMBI)
        WebX = st.number_input(f"Enter marks for Web X.0", min_value=1, max_value=80)
        marks.append(WebX)
        WT = st.number_input(
            f"Enter marks for Wireless Technology (WT)", min_value=1, max_value=80
        )
        marks.append(WT)
        AI = st.number_input(
            f"Enter marks for Artificial Intelligence (AI)", min_value=1, max_value=80
        )
        marks.append(AI)
        GIT = st.number_input(
            f"Enter marks for Green IT (GIT)", min_value=1, max_value=80
        )
        marks.append(GIT)

        # st.write(DMBI, WebX, WT, AI, GIT)

        submit_marks = st.form_submit_button(label="Submit Marks")

        if submit_marks:
            return marks


def encrypt_String(name, course, sem_year):
    name_enc = name.encode("iso-8859-1")
    course_enc = course.encode("iso-8859-1")
    sem_year_enc = sem_year.encode("iso-8859-1")

    encoded_bytes_name = base64.b64encode(name_enc)
    encoded_string_name = encoded_bytes_name.decode("utf-8")
    encoded_bytes_course = base64.b64encode(course_enc)
    encoded_string_course = encoded_bytes_course.decode("utf-8")
    encoded_bytes_sem = base64.b64encode(sem_year_enc)
    encoded_string_sem = encoded_bytes_sem.decode("utf-8")

    return encoded_string_name, encoded_string_course, encoded_string_sem


def addition(c1, c2, c3, c4, c5):
    maximum_marks = encrypt_number(80, public_key)
    cipher_add = c1 + c2 + c3 + c4 + c5
    total_marks_obtained = cipher_add
    # st.write("Addition", cipher_add)
    # st.write(decrypt_number(cipher_add, private_key))

    cipher_average = (c1 + c2 + c3 + c4 + c5) / 5

    cipher_percentage = cipher_add / 400 * 100
    #print(str(decrypt_number(percentage, private_key)) + "%")
    return cipher_add, cipher_average, cipher_percentage


def number_homomorphic():
    # Input numbers from user
    with st.form(key="my_form"):
        n1 = st.number_input(
            "First number", min_value=1, max_value=1000, value=5, step=1
        )
        n2 = st.number_input(
            "Second number", min_value=1, max_value=1000, value=5, step=1
        )
        operation = st.selectbox("Select an operation:", ["Addition", "Subtraction"])
        submit_button = st.form_submit_button(label="Submit")

        if submit_button:
            c1 = encrypt_number(n1, public_key)
            c2 = encrypt_number(n2, public_key)
            first_number = encode_string(str(c1))
            second_number = encode_string(str(c2))
            if operation == "Addition":
                # Perform addition and display results
                add = n1 + n2
                cipher_add = c1 + c2
                X = [[n1, n2]]
                y = [n1 + n2]
                # Create and train the linear regression model
                model = LinearRegression()
                model.fit(X, y)
                decrypt_add = decrypt_number(cipher_add, private_key)
                # Display the results
                st.write(
                    f'<p style ="font-size: 20px;"><b>The result of addition is: <span style="color: green;">{add}</span>',
                    unsafe_allow_html=True,
                )
                st.write(
                    f'<p style ="font-size: 20px;"><b>Addition of the encrypted numbers is: <span style="color:green;">{encode_string(str(cipher_add))}</span>',
                    unsafe_allow_html=True,
                )
                st.write(
                    f'<p style ="font-size: 20px;"><b>Addition of the decrypted numbers is: <span style="color: '
                    f'green;">{decrypt_add}</span>',
                    unsafe_allow_html=True,
                )
                # Predict the result using the trained model
                prediction = model.predict(X)
                st.write(
                    f'<p style ="font-size: 20px;"><b>Predicted result: <span style="color: '
                    f'green;">{prediction[0]}</span>',
                    unsafe_allow_html=True,
                )

            elif operation == "Subtraction":
                # Perform subtraction and display results
                sub = n1 - n2
                cipher_sub = c1 - c2
                X = [[n1, -n2]]
                y = [n1 - n2]
                # Create and train the linear regression model
                model = LinearRegression()
                model.fit(X, y)
                decrypt_sub = decrypt_number(cipher_sub, private_key)
                # Display the results
                st.write(
                    f'<p style ="font-size: 20px;"><b>The result of Subtraction is: <span style="color: green;">{sub}</span>',
                    unsafe_allow_html=True,
                )
                st.write(
                    f'<p style ="font-size: 20px;"><b>Addition of the encrypted numbers is: <span style="color:green;">{encode_string(str(cipher_sub))}</span>',
                    unsafe_allow_html=True,
                )
                st.write(
                    f'<p style ="font-size: 20px;"><b>Addition of the decrypted numbers is: <span style="color: '
                    f'green;">{decrypt_sub}</span>',
                    unsafe_allow_html=True,
                )
                # Predict the result using the trained model
                prediction = model.predict(X)
                st.write(
                    f'<p style ="font-size: 20px;"><b>Predicted result: <span style="color: '
                    f'green;">{prediction[0]}</span>',
                    unsafe_allow_html=True,
                )

            else:
                st.error("Pls Select an Operation!")


def marks_homomorphic():
    name = st.text_input("Name")
    roll_no = st.number_input("Roll number", min_value=1, max_value=1000)
    course = st.selectbox(
        "Select Course",
        ("Information Technology (IT)", "Computer Science (CS) ", "Electronics"),
    )
    sem_year = st.selectbox("Select Sem/Year", ("Semester-1", "Semester-2"))

    # Switch statement based on course and semester
    if course == "Information Technology (IT)" and sem_year == "Semester-1":
        # Perform some action for IT Semester 1
        print("Performing action for IT Semester 1")
        marks_list = IT()
        string_enc = encrypt_String(name, course, sem_year)
        if marks_list is not None:
            c1 = encrypt_number(roll_no, public_key)
            c2 = encrypt_number(marks_list[0], public_key)
            c3 = encrypt_number(marks_list[1], public_key)
            c4 = encrypt_number(marks_list[2], public_key)
            c5 = encrypt_number(marks_list[3], public_key)
            c6 = encrypt_number(marks_list[4], public_key)

            enc_roll_no = encode_string(str(c1))
            enc_dmbi = encode_string(str(c2))
            enc_webx = encode_string(str(c3))
            enc_wt = encode_string(str(c4))
            enc_ai = encode_string(str(c5))
            enc_git = encode_string(str(c6))

            total, average, percentage = addition(c2, c3, c4, c5, c6)
            enc_total = encode_string(str(total))
            enc_average = encode_string(str(average))
            enc_percentage = encode_string(str(percentage))

            sql = "INSERT INTO Encrypted (Name, `Roll no`, Course, `Sem/Year`, DMBI, `Web-X`, WT, AI, GIT, Total, Average, `Percentage %`)  VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            val = (
                string_enc[0],
                enc_roll_no,
                string_enc[1],
                string_enc[2],
                enc_dmbi,
                enc_webx,
                enc_wt,
                enc_ai,
                enc_git,
                enc_total,
                enc_average,
                enc_percentage,
            )
            cursor.execute(sql, val)
            db.commit()
            st.error("Encrypted")
            query = "SELECT * FROM Encrypted"
            df = pd.read_sql(query, db)
            st.dataframe(df)

            sql = "INSERT INTO Decrypted (Name, `Roll no`, Course, `Sem/Year`, DMBI, `Web-X`, WT, AI, GIT, Total, Average, `Percentage %`)  VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            val = (
                name,
                roll_no,
                course,
                sem_year,
                marks_list[0],
                marks_list[1],
                marks_list[2],
                marks_list[3],
                marks_list[4],
                decrypt_number(total, private_key),
                decrypt_number(average, private_key),
                decrypt_number(percentage, private_key),
            )
            cursor.execute(sql, val)
            db.commit()
            st.info("Decrypted")
            query = "SELECT * FROM Decrypted"
            df = pd.read_sql(query, db)
            st.dataframe(df)



    elif course == "Computer Science (CS)" and sem_year == "Semester-1":
        # Perform some action for CS Semester 1
        print("Performing action for CS Semester 1")
    elif course == "Electronics" and sem_year == "Semester-1":
        # Perform some action for Electronics Semester 1
        print("Performing action for Electronics Semester 1")
    else:
        # Handle invalid input
        print("Invalid input")


if __name__ == "__main__":

    # Set page title and header
    st.write(
        "<h1 style='font-size: 30px; font-family: Ethnocentric Rg; text-align:center;'>Secure Edu Guard</h1>"
        "<p style='font-size: 18px; font-family: Ethnocentric Rg; text-align:center;'>Homomorphic Marks Encryption & <br> Malware Detection 🔐</p>",
        unsafe_allow_html=True,
    )

    # Add horizontal line
    st.write(
        f'<hr style="background-color: red; margin-top: 0;'
        ' margin-bottom: 0; height: 3px; border: none; border-radius: 3px;">',
        unsafe_allow_html=True,
    )
    # Create option menu with icons
    selected = option_menu(
        menu_title=None,
        options=["Home", "Homomorphic", "Malware"],
        icons=["house", "file-lock", None],
        default_index=0,
        orientation="horizontal",
    )
    # Handle menu item selection
    if selected == "Home":
        print(selected)
    elif selected == "Homomorphic":
        print(selected)
        homo_select = st.selectbox("Select", ("Number", "Students Marks"))
        if homo_select == "Number":
            print(homo_select)
            number_homomorphic()
        elif homo_select == "Students Marks":
            print(homo_select)
            marks_homomorphic()
    elif selected == "Malware":
        print(selected)
        malware()

