import React from 'react'
import Repos from '../Components/Repos'
import NavBar from '../Components/Navbar'
import SStack from '../Components/SStack'
import BottomSocialNav from '../Components/bSocialNav'

export default class Software extends React.Component {

    styles = {
        container: {
            margin: '60px',
            //'background-color': 'grey'
        },
        repos: {
            'margin-left': '60px',

        },
        main: {
            //'background-color': 'grey'
            'margin-top': '8%'
        }

    }

    render() {
        return (
            <div style={this.styles.main}>
            <NavBar/>
            <div style={this.styles.container}><SStack/></div>
            <h2 style={this.styles.repos}>Github repositories</h2>
            <Repos/>
            <BottomSocialNav/>
            </div>
        )
    }
}