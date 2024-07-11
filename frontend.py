import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import random
import time
import pickle
import pandas as pd
import numpy as np
import shap
import tempfile
import matplotlib.pyplot as plt
import os
from PIL import Image, ImageTk
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
shap.initjs()
def explain_shap_values(shap_values, top_n=3):
    sorted_shap_values = sorted(shap_values.items(), key=lambda x: abs(x[1]), reverse=True)
    explanations = []
    for feature, shap_value in sorted_shap_values[:top_n]:
        if shap_value < -1:
            explanation = f"The feature {feature} has a very strong negative influence on the prediction."
        elif -1 <= shap_value < -0.5:
            explanation = f"The feature {feature} has a strong negative influence on the prediction."
        elif -0.5 <= shap_value < 0:
            explanation = f"The feature {feature} has a moderate negative influence on the prediction."
        elif 0 <= shap_value < 0.5:
            explanation = f"The feature {feature} has a moderate positive influence on the prediction."
        elif 0.5 <= shap_value < 1:
            explanation = f"The feature {feature} has a strong positive influence on the prediction."
        else:
            explanation = f"The feature {feature} has a very strong positive influence on the prediction."
        explanations.append(explanation)
    return explanations




#load the saved LR model from the pickle file
with open('lrclf.pkl', 'rb') as file:
    lr_clf = pickle.load(file)

# Load the k_best features CSV file
k_best_data = pd.read_csv('k_best.csv', usecols=lambda column: column != 'Unnamed: 0')
X_selected = k_best_data.drop('class', axis=1)
y_train_encoded = k_best_data['class']
X_train_scaled = scaler.fit_transform(X_selected)


# Assuming X_selected is your input data
background_data = X_train_scaled#.to_numpy()
explainer = shap.Explainer(lr_clf, background_data)

#Storing label mapping for use in prompting our chatbot to give explainable results
label_mapping = {
    'flag_SF': 'Connection Flag Successful',
    'same_srv_rate': 'Same Service Rate',
    'dst_host_srv_count': 'Destination Host Service Count',
    'logged_in': 'Logged In',
    'flag_S0': 'Connection Flag S0',
    'serror_rate': 'SYN Error Rate',
    'count': 'Connection Count',
    'service_http': 'Service HTTP',
    'service_private': 'Service Private',
    'dst_host_count': 'Destination Host Count'
}

# Create left window
left_window = tk.Tk()
left_window.title("Intrusion Detection Simulation")
left_window.geometry("540x360+250+70")  # Larger size for left window

# Load background image for left window
bg_image_left = Image.open("bg.jpg")
bg_image_left = ImageTk.PhotoImage(bg_image_left)
bg_label_left = tk.Label(left_window, image=bg_image_left)
bg_label_left.place(relwidth=1, relheight=1)

# Create labels to display SHAP mappings and explanations
shap_label = tk.Label(left_window, text="SHAP Mappings", font=("Arial", 10, "bold"), bg="#f0f0f0")
shap_label.place(x=20, y=50)

shap_values_label = tk.Label(left_window, text="", font=("Arial", 8), bg="#f0f0f0", justify=tk.LEFT)
shap_values_label.place(x=20, y=70)

explanations_label = tk.Label(left_window, text="Explanations", font=("Arial", 8, "bold"))
explanations_label.place(x=20, y=225)

explanations_output = tk.Text(left_window, width=50, height=7)
explanations_output.place(x=20, y=240)

# Function to set feature names for k_best_features
def set_feature_names(df, feature_names):
    df.columns = feature_names






def simulate_attack():
    class_selected_label.config(text="")
    # Clear previous result
    for widget in right_window.winfo_children():
        widget.destroy()
    #result_frame.destroy()
    selection = dropdown.get()
    if selection == 'No Intrusion':
        # Select a random row with 'normal' class from k_best data
        selected_row = k_best_data[k_best_data['class'] == 1].sample(n=1)
    elif selection == 'Intrusion':
        # Select a random row with 'intrusion' class from k_best data
        selected_row = k_best_data[k_best_data['class'] == 0].sample(n=1)
    elif selection =='Random':
        random_class = np.random.randint(2)
        if random_class == 1:
            class_selected_label.config(text="No Intrusion selected")
            selected_row = k_best_data[k_best_data['class'] == 1].sample(n=1)
        else:
            class_selected_label.config(text="Intrusion selected")
            selected_row = k_best_data[k_best_data['class'] == 0].sample(n=1)
    else:
        messagebox.showerror("Error", "Please select an option before attacking.")
        return  # Exit the function if no option is selected

    # Convert into a passable format for LR model.
    k_best_features = selected_row.drop('class', axis=1)

    # Set feature names for k_best_features
    set_feature_names(k_best_features, X_selected.columns)

    # Transform with correct feature names
    k_best_features_scaled = scaler.transform(k_best_features)
    print(k_best_features_scaled)
    # Assuming k_best_features_scaled contains the input data for which you want SHAP values
    shap_values = explainer.shap_values(k_best_features_scaled)
    
    print("Shap Values",shap_values)
    if len(shap_values[0]) == len(label_mapping):
        # Map SHAP values to feature labels dynamically
        shap_mapping = {label_mapping[key]: shap_values[0][i] for i, key in enumerate(label_mapping.keys())}
        print(shap_mapping)
    else:
        print("Error: Length of SHAP values does not match the number of features in label mapping.")
        print(len(shap_values), len(label_mapping))

    # Display SHAP mappings on screen
    shap_values_text = ""
    for label, value in shap_mapping.items():
        shap_values_text += f"- {label}: {value}\n"
    shap_values_label.config(text=shap_values_text)

    # Make prediction using LR model
    prediction = lr_clf.predict(k_best_features_scaled)
    print(prediction)
    if prediction == 1:
        label_text = "Normal Network Activity"
        label_color = "green"
        frame_bg_color = "green"  # Set background color to green for normal activity
    else:
        label_text = "Abnormal Activity Alert!\n Possible Intrusion Detected!"
        label_color = "red"
        frame_bg_color = "red"  # Set background color to red for abnormal activity

    explanations = explain_shap_values(shap_mapping)
    explanations_text = "\n".join(explanations)
    explanations_output.config(state=tk.NORMAL)
    explanations_output.delete(1.0, tk.END)
    explanations_output.insert(tk.END, explanations_text)
    explanations_output.config(state=tk.DISABLED)


#NEW
    # Update SHAP plots in the SHAP window
    generate_shap_plots(shap_values, X_selected.columns)



   # Update right window label with simulation result
    global result_frame  # Use global to access the existing frame
    result_frame = tk.Frame(right_window, bg=frame_bg_color, bd=1, relief=tk.SOLID)
    result_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    result_label = tk.Label(result_frame, text=label_text, font=("Arial", 16), bg=frame_bg_color, fg="white")
    result_label.pack(padx=10, pady=10)



# Create dropdown and button in left window
dropdown_label = tk.Label(left_window, text="Select:", font=("Arial", 10), bg="#f0f0f0")
dropdown_label.place(x=300, y=50)

options = ['No Intrusion', 'Intrusion', 'Random']
dropdown = ttk.Combobox(left_window, values=options, state="readonly")
dropdown.place(x=360, y=50)

# Set 'Random' as the default option
dropdown.current(options.index('Random'))

# Label to display which class was selected when "Random" is chosen
class_selected_label = tk.Label(left_window, text="", font=("Arial", 10), bg="#f0f0f0")
class_selected_label.place(x=360, y=80)


right_window = tk.Toplevel(left_window)
right_window.title("Simulation Result")
right_window.geometry("400x320+850+90")  # Position at (1000,200) and size 400x400

# Load background image for right window
bg_image_right = Image.open("bg.jpg")
bg_image_right = ImageTk.PhotoImage(bg_image_right)
bg_label_right = tk.Label(right_window, image=bg_image_right)
bg_label_right.place(relwidth=1, relheight=1)

# Function to update the result label
def update_result_label(label_text, frame_bg_color):
    global result_frame
    result_frame.destroy()  # Clear previous result
    result_frame = tk.Frame(right_window, bg=frame_bg_color, bd=1, relief=tk.SOLID)
    result_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    result_label = tk.Label(result_frame, text=label_text, font=("Arial", 16), bg=frame_bg_color, fg="white")
    result_label.pack(padx=10, pady=10)

# Create button to simulate attack
attack_button = tk.Button(left_window, text="Simulate Attack", command=simulate_attack, bg="grey", fg="white", font=("Arial", 11, "bold"), borderwidth=3, relief=tk.RAISED, highlightbackground="#333")
attack_button.place(x=360, y=120, width=120, height=40)

shap_window = tk.Toplevel(left_window)
shap_window.title("SHAP Visualizations")
shap_window.geometry("800x250+400+480")
  



def generate_shap_plots(shap_values, feature_names):
    shap.initjs()
    for widget in shap_window.winfo_children():
        widget.destroy()
    # Generate the SHAP force plot directly
    fig = shap.force_plot(explainer.expected_value, shap_values[0], feature_names=feature_names, matplotlib=True, show=False)
    
    # Save the plot as a temporary image file
    plt.savefig('scratch.png')
    
    # Load the saved image file into a PIL image
    shap_image = Image.open('scratch.png')
    
    # Resize the image if needed
    shap_image = shap_image.resize((800, 250), Image.LANCZOS)
    
    # Convert the PIL image to ImageTk format for displaying in Tkinter
    shap_image_tk = ImageTk.PhotoImage(shap_image)
    
    # Create a label in the shap_window to display the image
    shap_label = tk.Label(shap_window, image=shap_image_tk)
    shap_label.pack()
    
    # Keep a reference to the image to prevent garbage collection
    shap_label.image = shap_image_tk


# Start the GUI main loop
left_window.mainloop()
