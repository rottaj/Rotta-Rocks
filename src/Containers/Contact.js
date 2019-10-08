import React from 'react'
import NavBar from '../Components/Navbar'
import MailForm from '../Components/MailForm'
import BottomSocialNav from '../Components/bSocialNav'
import MessageContainer from './MessageContainer'
import MessageForm from '../Components/MessageForm'
//import socketIO from 'socket.io-client'
//const io = socketIO('localhost:3000/')

export default class Contact extends React.Component {

    styles = {
        main: {
            width: '100%',
            height: '100%'
        },
        header: {
            'text-align': 'center',
        },
        footer: {
            'text-align': 'center'
        }
    }

    render () {
        //this.sendSession()
        return (
            <div>
                <NavBar/>
                <div style={this.styles.main}>
                    <h2 style={this.styles.header}>Contact me!</h2>
                    <MailForm/>
                    <h5 style={this.styles.footer}> rottaj.business@gmail.com</h5>
                </div>
                {/*<MessageForm/>*/}
                <BottomSocialNav/>
            </div>
        )
    }
}