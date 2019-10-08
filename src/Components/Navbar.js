
import React from 'react';
//import { Nav, NavItem, Dropdown, DropdownItem, DropdownToggle, DropdownMenu, NavLink } from 'reactstrap';
import { Link } from 'react-router-dom'
import {
  Collapse,
  Navbar,
  NavbarToggler,
  Nav,
  NavItem,
  UncontrolledDropdown,
  DropdownToggle,
  DropdownMenu,
  DropdownItem } from 'reactstrap';
import { transparent } from 'material-ui/styles/colors';

export default class NavBar extends React.Component {

  state = {
    isCollapsed: false
  }

  styles = {
    main: {
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      //'width': '100%'
    },
    nav: {
      display: 'inline-block',
      'flex-flow': 'row',
      'padding-right': '85%',
      'padding-left': '10%',
      width: '100%',
    },
    item: {
      margin: '10%'
    },
    itemContact: {
      margin: '10%',
      'margin-left': '250%'
    }
  }

  toggleNavbar = () => {
    this.setState({
      isCollapsed: !this.state.isCollapsed
    })
  }

  render() {
    return (
      /*
        <div className="navBar" style={this.styles.main}>
          <ol className="jack" id="nav"><Link to="/">Jack</Link></ol>
          <ol className="software" id="nav"><Link to="/code">Software</Link></ol>
          <ol className="blogs" id="nav"><Link to="/blogs">Blogs</Link></ol>
          <ol className="myLife"id="nav"><Link to="/myLife">MyLife</Link></ol>
          <ol className ="contact"><Link to="/contact">Contact</Link></ol>
        </div>
      */
     <div style={this.styles.main}>
     <Navbar class="navbar navbar-transparent" color="light" light expand="md" style={this.styles.nav}>
     <NavbarToggler onClick={this.toggleNavbar} className="mr-2" />
     <Collapse isOpen={this.state.isCollapsed} navbar>
       <Nav className="ml-auto" navbar>
         <NavItem style={this.styles.item}>
          <Link to="/">Jack</Link>
         </NavItem>
         <NavItem style={this.styles.item}>
          <Link to="/code">Software</Link>
         </NavItem>
         <NavItem style={this.styles.item}>
          <Link to="/blogs">Blogs</Link>
         </NavItem>
         <NavItem style={this.styles.item}>
          <Link to="/myLife">MyLife</Link>
         </NavItem>
         <NavItem style={this.styles.itemContact}>
          <Link to="/contact">Contact</Link>
         </NavItem>
        </Nav>
      </Collapse>
      </Navbar>
      </div>
      
    );
  }
}