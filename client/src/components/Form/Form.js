import React from 'react'
import styled from 'styled-components'
import axios from 'axios';
import { Agent } from 'https';
import '../../assets/Error.scss';
import certs from '../../Certs/certs';
import { useNavigate } from 'react-router-dom';
import { GoogleFormProvider, useGoogleForm } from 'react-google-forms-hooks'

import form from './form.json'

import LongAnswerInput from './LongAnswerInput'
import CheckBoxInput from './CheckBoxInput'
import RadioInput from './RadioInput'
import LinearGrid from './LinearGridInput'


const FormContainer = styled.form`
  max-width: 600px;
  margin: 0 auto;
  padding: 50px 0;
`


const QuestionContainer = styled.div`
  margin-bottom: 20px;
`

const QuestionLabel = styled.h3`
  margin-bottom: 10px;
`

const QuestionHelp = styled.p`
  font-size: 0.8rem;
  color: #5c5c5c;
  margin-top: 0px;
`
const Questions = () => {
    return (
      <div>
        {form.fields.map((field) => {
          const { id } = field
  
          let questionInput = null
          switch (field.type) {
            case 'CHECKBOX':
              questionInput = <CheckBoxInput id={id} />
              break
            case 'RADIO':
              questionInput = <RadioInput id={id} />
              break
            case 'LONG_ANSWER':
              questionInput = <LongAnswerInput id={id} />
              break
            case 'LINEAR':
              questionInput = <LinearGrid id={id} />
              break
          }
  
          if (!questionInput) {
            return null
          }
  
          return (
            <QuestionContainer key={id}>
              <QuestionLabel>{field.label}</QuestionLabel>
              {questionInput}
              <QuestionHelp>{field.description}</QuestionHelp>
            </QuestionContainer>
          )
        })}
      </div>
    )
  }

  const Form = () => {
    const [errorMessage, setErrorMessage] = useState('');
    const history = useNavigate()
    const methods = useGoogleForm({ form })
    const onSubmit = async (data) => {
      await methods.submitToGoogleForms(data)
      try {
        const agent = new Agent({
          cert: certs.certFile,
          key: certs.keyFile,
        });
        const userInfo = JSON.parse(localStorage.getItem('userInfo'));
        const username = userInfo?.username;

        await axios.post(
            `https://localhost:9443/form_submit`,
            data,
            {
                headers: {
                    "Content-type": "application/json",
                    "USER-AUTH": userInfo?.role,
                    "USER-UUID": userInfo?.user_id,
                  },
                params: {
                    username
                }
            },
            { httpsAgent: agent },
          );
      } catch (error) {
        setErrorMessage('Error submitting form:' +error.response.data.message);
      }
      history("/profile")
    }
  
    return (
      <div>
      <GoogleFormProvider {...methods}>
        <FormContainer onSubmit={methods.handleSubmit(onSubmit)}>
          {form.title && (
            <>
              <h1>{form.title}</h1>
              {form.description && (
                <p style={{ fontSize: '.8rem' }}>{form.description}</p>
              )}
            </>
          )}
          <Questions />
          <button type='submit'>Submit form</button>
        </FormContainer>
      </GoogleFormProvider>
       {errorMessage && <div className="error-message"> <span className = "error-text">{errorMessage}</span> </div>}
       </div>
    )
  }
  
  export default Form