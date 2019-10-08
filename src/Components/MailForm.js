import React from 'react'
import socketIO from 'socket.io-client'
import { Button, Form, FormGroup, Label, Input, FormText,  } from 'reactstrap';

let io;
if(localStorage.getItem('userID')){
    console.log(localStorage.getItem('userID'))
    io = socketIO('localhost:8080', {
        transportOptions: {
            polling: {
            extraHeaders: {
                'Authorization': `Bearer ${localStorage.getItem('userID')}`
            }
            }
        }
    })
} else {
    console.log('else')
    io = socketIO('localhost:8080')
}


export default class MailForm extends React.Component {


    styles = {
        mainDiv: {
            'text-align': 'center'
        },
        area: {
            width: '100px',
            height: '100px'
        },
        text: {
            'font-size': '25px'
        }
    }


    sendState = (e) => {

        if(localStorage.userID === null || localStorage.userID === undefined) {
            console.log('swag')
            io.emit('session.new', {userContent: {
                first_name: e.target[0].value,
                last_name: e.target[1].value,
                email: e.target[2].value,
                subject: e.target[3].value,
                message: e.target[4].value
            }}, response => {
                console.log(`users id: ${response}`)
                io = socketIO('localhost:8080', {
                    transportOptions: {
                        polling: {
                        extraHeaders: {
                            'Authorization': `Bearer ${response}`
                        }
                        }
                    }
                })
                localStorage.setItem('userID', response)
            })
        } else {
            return null
        }
    }


    render() {
        return (

            <Form style={this.styles.mainDiv}>
                <FormGroup>
                    <Label for="contactName">Name</Label>
                    <Input type="name" name="name" id="contactName" placeholder="with a placeholder" />
                </FormGroup>
                <FormGroup>
                    <Label for="contactEmail">Email</Label>
                    <Input type="email" name="email" id="contactName" placeholder="password placeholder" />
                </FormGroup>
                <FormGroup>
                    <Label for="contactSubject">Subject</Label>
                    <Input type="subject" name="subject" id="contactSubject" placeholder="password placeholder" />
                </FormGroup>
                <FormGroup>
                    <Label for="contactMessage">Message</Label>
                    <Input type="message" name="message" id="contactMessage" placeholder="password placeholder" />
                </FormGroup>
            
            </Form>

        )
    }
}

