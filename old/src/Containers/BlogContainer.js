import React from 'react'
import NavBar from '../Components/Navbar'
import Blog from '../Components/Blog'
import Grid from '@material-ui/core/Grid'
import BottomSocialNav from '../Components/bSocialNav'

export default class BlogContainer extends React.Component {

    state = {
        blogs: []
    }

    styles = {
        container: {
            //'margin-left': '3%',
            //'margin-right': '3%'
            margin: '5%',
            'margin-top': '10%'
        }
    }

    fetchBlogs = () => {
        fetch('https://api.rss2json.com/v1/api.json?rss_url=https://medium.com/feed/@jackrotta12')
            .then(res => res.json())
            .then(data => this.setState({blogs: data.items}))
    }

    componentDidMount() {
        this.fetchBlogs()
    }

    
    render() {
        console.log(this.state)
        return (
            <div style={this.styles.container}>
            <NavBar/>
            <Grid item xs={12}>
                {this.state.blogs.map(blog => <Blog blog={blog}/>) }           
            </Grid>
            <BottomSocialNav/>
            </div>
        )
    }
}