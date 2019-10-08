import React from 'react'
import Message from '../Components/Message'
import MessageForm from '../Components/MessageForm'

// This is a work in progress... Provides a way for real time messaging with session based authenication -- JSON web tokens

export default class MessageContainer extends React.Component {


    render() {
        console.log(this.props)
        return (
            <div>
                {console.log(this.props.messages)}
                {this.props.messages.map(msg => <Message message={msg}/>)}

            </div>
        )
    }
}