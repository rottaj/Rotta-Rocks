import React from 'react'
import Repos from '../Components/Repos'
import NavBar from '../Components/Navbar'
import SocialMediaNav from '../Components/SocialNav'
import PopRepos from './PopRepos'
import BottomSocilNav from '../Components/bSocialNav'
//import socketIO from 'socket.io-client'
import '../Home.css'
//import {Link} from 'react-router-dom'
 
//const io = socketIO('localhost:3000')


export default class Home extends React.Component {

    styles = {
      projects: {
        'margin-left': '5%',
        'margin-right': '5%',
        //'background-color': 'grey',
        'border-radius': '26px',
        'text-align': 'center'
      }
    }

    render() {
      return(
          <div class="mainContainer">
            <div class="first-pic">
            <NavBar/>
              <div class="ptext">
                  Jack Rotta

                  <p>Software Developer.</p>
                  <SocialMediaNav/>
              </div>
            </div>

            <section class="section section-dark">
              <p className = "section-text">
                  <h2>About me</h2>


                <p>Certified Full-Stack Web Developer with a passion to learn and create.</p>
                <p>Demonstrating the process through blogs and code</p>
              </p>
            </section>

            <div class="pimg2">
              <div class="ptext2">
                <h2 style={this.styles.projects}>Pinned Projects</h2>
              </div>
              <div class="popRepos">
              <PopRepos/>
              </div>
            </div>
 
            <div class="first-pic">
              <div class="ptext">
                  coming soon!
              </div>
            </div>
            <BottomSocilNav/>
          </div>



      )
    }
}