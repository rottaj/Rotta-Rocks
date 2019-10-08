import React from 'react'
import { Button, Form } from 'semantic-ui-react'
import socketIO from 'socket.io-client'
import MessageContainer from '../Containers/MessageContainer'

const io = socketIO('localhost:8080')

 // Work in progress... provides real time messaging

export default class MessageForm extends React.Component {

    state = {
        messages: []
    }

    componentDidMount() {
        io.on('get.messages', (req) => {
            console.log(req.messageHistory, this.state.messages)
            this.setState({messages: [...this.state.messages, ...req.messageHistory]})
        })
    }

    sendMessage = (e) => {
        console.log('sent message')
        io.emit('message.new', {messageContent: {message: e.target[0].value, userId: localStorage.userID}}, response => {
            this.setState({messages: [...this.state.messages, response]})
        })
    }

    /*
    setValue = (e) => {
        e.target[0].value = ""
    }
    */

    render() {
        console.log(this.state.messages)
        return (
                <div>
                    <MessageContainer messages={this.state.messages}/>
                    <Form onSubmit={e => this.sendMessage(e)}>
                        <Form.Field>
                            <label>Message: </label>
                            <textarea placeholder="scrubmuffin"></textarea>
                        </Form.Field>
                        <Button type='submit'>Send Message</Button>
                    </Form>
                </div>
        )
    }
}