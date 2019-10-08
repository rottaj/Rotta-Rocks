import React from 'react'
import StarRepo from '../Components/StarRepo'

export default class PopRepos extends React.Component {

    state = {
        repos: []
    }

    fetchRepos = () => {
        fetch('https://api.github.com/users/rottaj/starred')
        .then(res => res.json())
        .then(data => {
            console.log(data)
            this.setState({repos: data})
        })
    }

    componentDidMount = () => {
        this.fetchRepos()
    }

    styles = {
        card: {
            display: 'flex',
            'flex-flow': 'row wrap',
            'text-align': 'center',
        }
    }

    render() {
        console.log(this.state.repos)
        return (
            <div style={this.styles.card}>
                {this.state.repos.map(rep => <StarRepo repo={rep}/>)}
            </div>
        )
    }
}