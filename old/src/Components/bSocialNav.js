import React from 'react'
import Grid from '@material-ui/core/Grid'

export default class BottomSocialNav extends React.Component {

    styles = {
        li: {
            display: 'flex',
            'flex-direction': 'row',
            height: '200px'
        },
        ic: {
            height: '50px'
        },
        pos: {
            //position: 'fixed',
            'padding-left': '32%',
            'padding-right': '30%',
            //bottom: 0
        }
    }

    render() {
        return (
            <Grid container style={this.styles.pos}>
                <ul className="ig" id="snav"><a href="https://www.instagram.com/jackrotta"><img style={this.styles.ic} src={require('../ig_icon')}></img></a></ul>
                <ul className="twitter" id="snav"><a href="https://twitter.com/rottaj1"><img style={this.styles.ic} src={require('../tw_icon')}></img></a></ul>
                <ul styles={this.styles.gh} className="gh" id="snav"><a href="https://www.github.com/rottaj"><img style={this.styles.ic} src={require('../gh_icon')}></img></a></ul>
                <ul className="sc" id="snav"><a href="https://www.snapchat.com/add/jackrotta2"><img style={this.styles.ic} src={require('../sc_icon')}></img></a></ul>
                <ul className ="linkedin" id="snav"><a href="https://www.linkedin.com/in/jack-rotta-656861186/"><img style={this.styles.ic} src={require('../li_icon')}></img></a></ul>
            </Grid>
        )
    }
}