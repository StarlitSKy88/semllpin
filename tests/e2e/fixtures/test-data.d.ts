export declare const TestUsers: {
    newUser: {
        username: string;
        email: string;
        password: string;
        profile: {
            firstName: string;
            lastName: string;
            bio: string;
        };
    };
    annotationCreator: {
        username: string;
        email: string;
        password: string;
        profile: {
            firstName: string;
            lastName: string;
            bio: string;
        };
    };
    rewardDiscoverer: {
        username: string;
        email: string;
        password: string;
        profile: {
            firstName: string;
            lastName: string;
            bio: string;
        };
    };
    socialUser: {
        username: string;
        email: string;
        password: string;
        profile: {
            firstName: string;
            lastName: string;
            bio: string;
        };
    };
    admin: {
        username: string;
        email: string;
        password: string;
        role: string;
    };
};
export declare const TestAnnotations: {
    pleasant: {
        title: string;
        description: string;
        category: string;
        intensity: number;
        rewardAmount: number;
        location: {
            name: string;
            latitude: number;
            longitude: number;
            address: string;
        };
        tags: string[];
        expectedInteractions: {
            likes: number;
            comments: number;
            shares: number;
        };
    }[];
    unpleasant: {
        title: string;
        description: string;
        category: string;
        intensity: number;
        rewardAmount: number;
        location: {
            name: string;
            latitude: number;
            longitude: number;
            address: string;
        };
        tags: string[];
        expectedInteractions: {
            likes: number;
            comments: number;
            shares: number;
        };
    }[];
    neutral: {
        title: string;
        description: string;
        category: string;
        intensity: number;
        rewardAmount: number;
        location: {
            name: string;
            latitude: number;
            longitude: number;
            address: string;
        };
        tags: string[];
        expectedInteractions: {
            likes: number;
            comments: number;
            shares: number;
        };
    }[];
};
export declare const TestLocations: {
    newYork: {
        city: string;
        country: string;
        coordinates: {
            name: string;
            lat: number;
            lng: number;
        }[];
    };
    beijing: {
        city: string;
        country: string;
        coordinates: {
            name: string;
            lat: number;
            lng: number;
        }[];
    };
};
export declare const TestScenarios: {
    userJourneys: {
        newUserOnboarding: {
            name: string;
            steps: string[];
            expectedDuration: number;
            successCriteria: string[];
        };
        annotationCreation: {
            name: string;
            steps: string[];
            expectedDuration: number;
            successCriteria: string[];
        };
        rewardDiscovery: {
            name: string;
            steps: string[];
            expectedDuration: number;
            successCriteria: string[];
        };
        socialInteraction: {
            name: string;
            steps: string[];
            expectedDuration: number;
            successCriteria: string[];
        };
    };
    performanceTests: {
        loadTesting: {
            concurrent_users: number[];
            test_duration: number;
            ramp_up_time: number;
            endpoints: string[];
        };
        stressTestScenarios: ({
            name: string;
            concurrent_users: number;
            test_endpoint: string;
            expected_response_time: number;
            operations_per_user?: undefined;
        } | {
            name: string;
            concurrent_users: number;
            test_endpoint: string;
            operations_per_user: number;
            expected_response_time?: undefined;
        })[];
    };
    errorScenarios: {
        name: string;
        trigger: string;
        expectedBehavior: string;
    }[];
};
export declare const TestData: {
    users: {
        newUser: {
            username: string;
            email: string;
            password: string;
            profile: {
                firstName: string;
                lastName: string;
                bio: string;
            };
        };
        annotationCreator: {
            username: string;
            email: string;
            password: string;
            profile: {
                firstName: string;
                lastName: string;
                bio: string;
            };
        };
        rewardDiscoverer: {
            username: string;
            email: string;
            password: string;
            profile: {
                firstName: string;
                lastName: string;
                bio: string;
            };
        };
        socialUser: {
            username: string;
            email: string;
            password: string;
            profile: {
                firstName: string;
                lastName: string;
                bio: string;
            };
        };
        admin: {
            username: string;
            email: string;
            password: string;
            role: string;
        };
    };
    annotations: {
        pleasant: {
            title: string;
            description: string;
            category: string;
            intensity: number;
            rewardAmount: number;
            location: {
                name: string;
                latitude: number;
                longitude: number;
                address: string;
            };
            tags: string[];
            expectedInteractions: {
                likes: number;
                comments: number;
                shares: number;
            };
        }[];
        unpleasant: {
            title: string;
            description: string;
            category: string;
            intensity: number;
            rewardAmount: number;
            location: {
                name: string;
                latitude: number;
                longitude: number;
                address: string;
            };
            tags: string[];
            expectedInteractions: {
                likes: number;
                comments: number;
                shares: number;
            };
        }[];
        neutral: {
            title: string;
            description: string;
            category: string;
            intensity: number;
            rewardAmount: number;
            location: {
                name: string;
                latitude: number;
                longitude: number;
                address: string;
            };
            tags: string[];
            expectedInteractions: {
                likes: number;
                comments: number;
                shares: number;
            };
        }[];
    };
    locations: {
        newYork: {
            city: string;
            country: string;
            coordinates: {
                name: string;
                lat: number;
                lng: number;
            }[];
        };
        beijing: {
            city: string;
            country: string;
            coordinates: {
                name: string;
                lat: number;
                lng: number;
            }[];
        };
    };
    scenarios: {
        userJourneys: {
            newUserOnboarding: {
                name: string;
                steps: string[];
                expectedDuration: number;
                successCriteria: string[];
            };
            annotationCreation: {
                name: string;
                steps: string[];
                expectedDuration: number;
                successCriteria: string[];
            };
            rewardDiscovery: {
                name: string;
                steps: string[];
                expectedDuration: number;
                successCriteria: string[];
            };
            socialInteraction: {
                name: string;
                steps: string[];
                expectedDuration: number;
                successCriteria: string[];
            };
        };
        performanceTests: {
            loadTesting: {
                concurrent_users: number[];
                test_duration: number;
                ramp_up_time: number;
                endpoints: string[];
            };
            stressTestScenarios: ({
                name: string;
                concurrent_users: number;
                test_endpoint: string;
                expected_response_time: number;
                operations_per_user?: undefined;
            } | {
                name: string;
                concurrent_users: number;
                test_endpoint: string;
                operations_per_user: number;
                expected_response_time?: undefined;
            })[];
        };
        errorScenarios: {
            name: string;
            trigger: string;
            expectedBehavior: string;
        }[];
    };
};
export default TestData;
//# sourceMappingURL=test-data.d.ts.map