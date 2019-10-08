import React from 'react';
import logo from './logo.svg';
import './App.css';
import Home from './Containers/Home'
import Software from './Containers/Software'
import {HashRouter, Route} from 'react-router-dom'
import Contact from './Containers/Contact';
import About from './Containers/About';
import Blogs from './Containers/BlogContainer';
import PictureContainer from './Containers/PictureContainer'

export default class App extends React.Component {
  render() {
    return (
      <HashRouter>
        <Route exact path = '/' component = {Home}/>
        <Route exact path = '/code' component = {Software}/>
        <Route exact path = '/blogs' component = {Blogs}/>
        <Route exact path = '/myLife' component = {PictureContainer}/>
        <Route exact path = '/contact' component = {Contact}/>
      </HashRouter>
    )
  }
}

