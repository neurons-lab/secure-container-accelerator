import streamlit as st
from streamlit_chat import message
import boto3
from langchain.chat_models import ChatOpenAI
from langchain.prompts.chat import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    AIMessagePromptTemplate,
    HumanMessagePromptTemplate,
    MessagesPlaceholder
)
from langchain.schema import (
    AIMessage,
    HumanMessage,
    SystemMessage
)
from langchain.memory import ConversationBufferMemory
from langchain.chains import ConversationChain


# Create an SSM client using Boto3
ssm = boto3.client('ssm')

# Set SSM Parameter Store name for the OpenAI API key and the OpenAI Model Engine
API_KEY_PARAMETER_PATH = '/openai/api_key'

# Get the API key from the SSM Parameter Store
openai_api_key = ssm.get_parameter(
    Name=API_KEY_PARAMETER_PATH, 
    WithDecryption=True
)['Parameter']['Value']

prompt = ChatPromptTemplate.from_messages([
    SystemMessagePromptTemplate.from_template("""I want you to act as a mental health adviser. You are Virtual Mental Health Adviser.
        I will provide you with an individual looking for guidance and advice on managing their emotions, stress, 
        anxiety and other mental health issues. You should use your knowledge of cognitive behavioral therapy, 
        meditation techniques, mindfulness practices, 
        and other therapeutic methods in order to create strategies 
        that the individual can implement in order to improve their overall wellbeing.
        Ask questions to get to know the individual and their situation. 
        Start with introduction and initiate convesation with me to get my situation."""),
    MessagesPlaceholder(variable_name="history"),
    HumanMessagePromptTemplate.from_template("{input}")
])

chat = ChatOpenAI(temperature=0.9, openai_api_key=openai_api_key)
memory = ConversationBufferMemory(return_messages=True)
conversation = ConversationChain(memory=memory, prompt=prompt, llm=chat)

first_ai_replica = conversation.predict(input="Start with introduction and initiate convesation with me to get my situation.")

# Set the page title and icon
st.set_page_config(
    page_title="Virtual Mental Health Adviser",
    page_icon=":robot:"
)

# Set the page header
st.header("Streamlit Chat - Demo")
#st.markdown("[Github](https://github.com/kobrinartem/chatgpt-streamlit-demo)")

if 'initial' not in st.session_state:
    st.session_state['initial'] = first_ai_replica

if 'generated' not in st.session_state:
    st.session_state['generated'] = []

if 'past' not in st.session_state:
    st.session_state['past'] = []

def query(message):
	response = conversation.predict(input=message)
	return response

def get_text():
    message = st.text_input('You:', '')
    return message


# Get the user's message
user_input = get_text()



if user_input:
    output = query(user_input)

    st.session_state.past.append(user_input)
    st.session_state.generated.append(output)

if st.session_state['generated']:

    for i in range(len(st.session_state['generated'])-1, -1, -1):
        st.markdown(f'**Bot:** {st.session_state["generated"][i]}')
        st.markdown(f'**You:** {st.session_state["past"][i]}')
# Display the first bot's message
st.markdown(f'**Bot:** {st.session_state["initial"]}')